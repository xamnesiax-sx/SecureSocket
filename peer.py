import proto


class peer(object):

    def __init__(self):
        
        self.socket = proto.socket_wrapper()

        self.socket.set_options("", "")
