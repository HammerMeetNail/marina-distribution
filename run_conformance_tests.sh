#!/bin/bash

# Exit immediately if a command exits with a non-zero status.
set -e

# Define paths relative to the script's location (which is the project root)
SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )
PROJECT_ROOT="$SCRIPT_DIR" # Project root is where the script is
TEST_BIN="$PROJECT_ROOT/tests/conformance.test" # Use existing test binary in tests/
ENV_VARS_FILE="$PROJECT_ROOT/tests/.env_vars"    # Env vars file in tests/
REGISTRY_LOG="$PROJECT_ROOT/tests/registry.log" # Log file in tests/
REGISTRY_MAIN="$PROJECT_ROOT/cmd/registry/main.go" # Main Go file

# Check if required files exist
if [ ! -f "$REGISTRY_MAIN" ]; then
  echo "Error: Registry main file not found at $REGISTRY_MAIN"
  exit 1
fi
if [ ! -f "$TEST_BIN" ]; then
  echo "Error: Conformance test binary not found at $TEST_BIN"
  echo "Please ensure 'conformance.test' exists in the 'tests' directory."
  exit 1
fi
if [ ! -f "$ENV_VARS_FILE" ]; then
  echo "Error: Environment variables file not found at $ENV_VARS_FILE"
  exit 1
fi


# More robust cleanup function
cleanup() {
  echo "--- Cleaning up ---"
  if [[ -z "$REGISTRY_PID" ]]; then
    echo "Registry PID not set. Skipping cleanup."
    return
  fi

  if ps -p $REGISTRY_PID > /dev/null; then
    echo "Attempting graceful shutdown of registry server (PID: $REGISTRY_PID)..."
    # Try SIGTERM first
    kill $REGISTRY_PID 2>/dev/null
    sleep 1

    if ps -p $REGISTRY_PID > /dev/null; then
      echo "Graceful shutdown failed, trying to kill process group (PID: $REGISTRY_PID)..."
      # Try SIGTERM on the process group
      kill -- -$REGISTRY_PID 2>/dev/null
      sleep 1

      if ps -p $REGISTRY_PID > /dev/null; then
        echo "Process group kill failed, sending SIGKILL to PID $REGISTRY_PID..."
        # Try SIGKILL on the specific PID
        kill -9 $REGISTRY_PID 2>/dev/null
        sleep 0.5

         if ps -p $REGISTRY_PID > /dev/null; then
           echo "SIGKILL failed, sending SIGKILL to process group -$REGISTRY_PID..."
           # Try SIGKILL on the process group as a last resort
           kill -9 -- -$REGISTRY_PID 2>/dev/null
           sleep 0.5
         fi
      fi
    fi

    if ps -p $REGISTRY_PID > /dev/null; then
       echo "ERROR: Failed to stop registry server (PID: $REGISTRY_PID) even with SIGKILL."
    else
       echo "Registry server (PID: $REGISTRY_PID) stopped."
    fi
  else
    echo "Registry server (PID: $REGISTRY_PID) was not running."
  fi

  # Final check: Explicitly kill any process still listening on port 5000
  echo "Performing final check on port 5000..."
  LEFTOVER_PIDS=$(lsof -ti tcp:5000 || true) # Get PIDs, ignore error if none found

  if [[ -n "$LEFTOVER_PIDS" ]]; then
      echo "WARNING: Port 5000 still occupied by PID(s): $LEFTOVER_PIDS. Attempting final kill..."
      # Force kill remaining processes
      kill -9 $LEFTOVER_PIDS
      sleep 0.5 # Brief pause

      # Verify port is free now
      if lsof -ti tcp:5000 > /dev/null ; then
          echo "ERROR: Failed to free port 5000 even after final kill attempt."
      else
          echo "Port 5000 successfully freed after final kill attempt."
      fi
  else
      echo "Port 5000 is confirmed free."
  fi
}

# Trap EXIT signal to run cleanup function
# Trap EXIT signal to run cleanup function
trap cleanup EXIT

echo "--- Checking Port 5000 ---"
# Get PID(s) listening on TCP port 5000, ensure command doesn't exit script if port is free
PIDS=$(lsof -ti tcp:5000 || true)

if [[ -n "$PIDS" ]]; then
    echo "WARNING: Port 5000 is currently in use by the following process(es):"
    # Get process command details
    PROCESS_INFO=$(ps -p $PIDS -o pid=,command=)
    echo "$PROCESS_INFO" | sed 's/^/  /' # Indent output
    echo "" # Newline for clarity

    # Check if the process command contains 'podman' or 'docker' (case-insensitive)
    # Use extended regex (-E) for alternation (|)
    if echo "$PROCESS_INFO" | grep -iqE 'podman|docker'; then
        echo "Detected Podman or Docker using port 5000."
        echo "Proceeding with tests against the existing container."
        # Unset REGISTRY_PID so cleanup doesn't try to kill the external process
        REGISTRY_PID=""
        # Skip starting a new server instance
        SKIP_SERVER_START=true # Don't start a new server
    else
        # Ask user for confirmation to kill non-container process
        read -p "Do you want to attempt to kill this non-container process(es)? (y/N): " -n 1 -r REPLY
        echo # Move to new line after input

        if [[ "$REPLY" =~ ^[Yy]$ ]]; then
        echo "Attempting to kill process(es) $PIDS..."
        # Use kill -9 for forceful termination as requested previously
        kill -9 $PIDS
        # Wait a moment for processes to terminate
        sleep 1

        # Check again if the port is free
        if lsof -ti tcp:5000 > /dev/null ; then
            echo "ERROR: Failed to free port 5000 after killing process(es). Exiting."
            echo "You may need to investigate further or try killing manually:"
            echo "  lsof -ti tcp:5000 | xargs kill -9"
                exit 1
            else
                echo "Port 5000 is now free."
                SKIP_SERVER_START=false # We killed it, so we need to start a new one
            fi
        else
            # User declined to kill the non-container process
            echo "Proceeding with tests against the existing process on port 5000."
            # Unset REGISTRY_PID so cleanup doesn't try to kill the external process
            REGISTRY_PID=""
            # Skip starting a new server instance
            SKIP_SERVER_START=true # Don't start a new server
        fi # End of kill confirmation if/else
    fi # End of podman/docker check if/else
else
    echo "Port 5000 is free."
    SKIP_SERVER_START=false # Port was free, so we need to start one
fi

# Only start the server if SKIP_SERVER_START is false
if [ "$SKIP_SERVER_START" != true ]; then
    echo "--- Starting Registry Server ---"
    # No need to cd, script is already in project root
    # Start the server using 'go run' in the background, redirect stdout/stderr to a log file
# Use 'setsid' or similar if 'go run' doesn't create a process group correctly for cleanup,
# but killing the process group via `kill -- -$PID` is generally preferred.
    go run "$REGISTRY_MAIN" > "$REGISTRY_LOG" 2>&1 &
    REGISTRY_PID=$!
    # No need to cd back, stay in project root

    echo "Registry server started via 'go run' (PID: $REGISTRY_PID). Logs: $REGISTRY_LOG"

    # Wait for the server to be ready (simple sleep, adjust as needed or implement a health check)
    echo "Waiting for server to initialize..."
    sleep 3 # Adjust this delay if needed

    # Check if server process is still running
    if ! ps -p $REGISTRY_PID > /dev/null; then
      echo "Registry server failed to start. Check logs: $REGISTRY_LOG"
      exit 1
    fi
    echo "Server appears to be running."
else
    echo "Skipping server start as requested or because port was occupied and kill declined."
fi


echo "--- Sourcing Environment Variables ---"
source "$ENV_VARS_FILE"
echo "Environment variables sourced from $ENV_VARS_FILE"


echo "--- Running Conformance Tests ---"
# Run the existing test binary, passing any arguments provided to this script
"$TEST_BIN" -test.v "$@" # -test.v for verbose output
TEST_EXIT_CODE=$?
echo "--- Conformance Tests Finished (Exit Code: $TEST_EXIT_CODE) ---"

# Cleanup is handled by the trap

exit $TEST_EXIT_CODE
