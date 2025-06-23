import requests
import time
import sys
import itertools
from datetime import datetime

def animate_loading():
    """Simple animation to show that training is in progress"""
    spinner = itertools.cycle(['|', '/', '-', '\\'])
    start_time = datetime.now()
    
    while True:
        elapsed = datetime.now() - start_time
        elapsed_seconds = elapsed.total_seconds()
        minutes = int(elapsed_seconds // 60)
        seconds = int(elapsed_seconds % 60)
        
        sys.stdout.write(f"\rTraining in progress {next(spinner)} (Elapsed: {minutes:02d}:{seconds:02d}) ")
        sys.stdout.flush()
        time.sleep(0.1)

# Give the main app time to start
print("Waiting for the server to start...")
for i in range(5, 0, -1):
    sys.stdout.write(f"\rStarting in {i} seconds...")
    sys.stdout.flush()
    time.sleep(1)
    
print("\nConnecting to server...")

# Now train the model
print("Initiating model training...")
try:
    # Start animation in a separate thread
    import threading
    animation_thread = threading.Thread(target=animate_loading)
    animation_thread.daemon = True
    animation_thread.start()
    
    # Make the training request
    start_time = time.time()
    response = requests.post("http://localhost:8000/train")
    end_time = time.time()
    
    # Print results
    print(f"\nTraining completed in {end_time - start_time:.2f} seconds!")
    print(f"Response: {response.json()}")
    
except requests.exceptions.ConnectionError:
    print("\nError: Could not connect to the server. Make sure the FastAPI app is running on http://localhost:8000")
except Exception as e:
    print(f"\nError training model: {e}")
finally:
    print("\nProcess completed.")