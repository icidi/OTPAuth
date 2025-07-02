import threading

class Timer(threading.Thread):

    def __init__(self, interval, function, *args, **kwargs):
        super().__init__()
        self.stopped = threading.Event()
        self.interval = interval
        self.function = function
        self.args = args
        self.kwargs = kwargs

    
    def run(self):
        while not self.stopped.wait(self.interval):
            self.function(*self.args, **self.kwargs)
            

    def stop(self):
        self.stopped.set()

# use <instance>.start() to start the timer

