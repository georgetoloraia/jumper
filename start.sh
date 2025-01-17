#!/bin/bash

PROGRAM="./stepscpp"  # Path to your program
RUN_TIME=120          # Run time in seconds (2 minutes)
REST_TIME=10          # Rest time in seconds

while true; do
    echo "Starting $PROGRAM..."
    $PROGRAM &                # Run the program in the background
    PID=$!                    # Get the process ID of the program
    echo "Program started with PID $PID"

    sleep $RUN_TIME           # Wait for the run time
    echo "Stopping $PROGRAM (PID $PID)..."
    kill $PID                 # Stop the program
    wait $PID 2>/dev/null     # Ensure the process is terminated
    echo "Program stopped."

    echo "Resting for $REST_TIME seconds..."
    sleep $REST_TIME          # Wait for the rest time
done
