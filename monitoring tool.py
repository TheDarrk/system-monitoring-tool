import time
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

class MyHandler(FileSystemEventHandler):
    def on_created(self, event):
        print(f"File Created: {event.src_path}")

    def on_deleted(self, event):
        print(f"File Deleted: {event.src_path}")

    def on_modified(self, event):
        print(f"File Modified: {event.src_path}")

    def on_moved(self, event):
        print(f"File Moved: {event.src_path} -> {event.dest_path}")

if __name__ == "__main__":
    path = "C:/Users/ankit/OneDrive/Desktop/A test"  #your target folder

    event_handler = MyHandler()  
    observer = Observer()
    observer.schedule(event_handler, path, recursive=True)  

    observer.start()
    try:
        print("Monitoring started... Press Ctrl+C to stop.")
        while True:
            time.sleep(1) 
    except KeyboardInterrupt:
        observer.stop()  
        print("Monitoring stopped.")

    observer.join()
