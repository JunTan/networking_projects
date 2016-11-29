import wan_optimizer
import utils
import tcp_packet

class WanOptimizer(wan_optimizer.BaseWanOptimizer):
    """ WAN Optimizer that divides data into variable-sized
    blocks based on the contents of the file.

    This WAN optimizer should implement part 2 of project 4.
    """

    # The string of bits to compare the lower order 13 bits of hash to
    GLOBAL_MATCH_BITSTRING = '0111011001010'

    def __init__(self):
        wan_optimizer.BaseWanOptimizer.__init__(self)
        # Add any code that you like here (but do not add any constructor arguments).
        self.hash_key = {}
        self.hash_data = {}
        self.src_dest_buffer = {}
        return

    def receive(self, packet):
        """ Handles receiving a packet.

        Right now, this function simply forwards packets to clients (if a packet
        is destined to one of the directly connected clients), or otherwise sends
        packets across the WAN. You should change this function to implement the
        functionality described in part 2.  You are welcome to implement private
        helper fuctions that you call here. You should *not* be calling any functions
        or directly accessing any variables in the other middlebox on the other side of 
        the WAN; this WAN optimizer should operate based only on its own local state
        and packets that have been received.
        """
        if packet.dest in self.address_to_port:
            # The packet is destined to one of the clients connected to this middlebox;
            # send the packet there.
            src = packet.src
            dest = packet.dest
            is_fin = packet.is_fin
            is_raw_data = packet.is_raw_data
            if (src, dest) not in self.src_dest_buffer:
                self.src_dest_buffer[(src, dest)] = ""

            if not is_raw_data:
                # Decode the hash, replace the hash with actual data
                data = self.hash_key[packet.payload]
            else:
                # Extract the data
                data = packet.payload
            
            # Append the data to buffer
            self.src_dest_buffer[(src, dest)] += data
            data_to_send = self.findDelimiter(src, dest)
            if data_to_send:
                if data_to_send not in self.hash_data:
                    self.create_mapping(data_to_send)
                while(data_to_send):
                    data = data_to_send[ :utils.MAX_PACKET_SIZE]
                    packet = tcp_packet.Packet(src, dest, True, False, data)
                    self.send(packet, self.address_to_port[packet.dest])
                    data_to_send = data_to_send[utils.MAX_PACKET_SIZE: ]
            elif is_fin:
                data_to_send = self.src_dest_buffer[(src, dest)]
                if data_to_send not in self.hash_data:
                    self.create_mapping(data_to_send)
                while(True):
                    data = data_to_send[ :utils.MAX_PACKET_SIZE]
                    if not data:
                        packet = tcp_packet.Packet(src, dest, True, True, data)
                        self.send(packet, self.address_to_port[packet.dest])
                        self.src_dest_buffer[(src, dest)] = ""
                        break
                    packet = tcp_packet.Packet(src, dest, True, False, data)
                    self.send(packet, self.address_to_port[packet.dest])
                    data_to_send = data_to_send[utils.MAX_PACKET_SIZE: ]
        else:
            # The packet must be destined to a host connected to the other middlebox
            # so send it across the WAN.
            self.send(packet, self.wan_port)

    def findDelimiter(self, src, dest):
        """ Look for the delimiter in the buff of (src, dest)
        Return False is the block-delimiter is not found
        Return the data if the block-delimiter is found and delete this part
        of data from the buff
        """

    def create_mapping(self, data):
        key = utils.get_hash(data)
        self.hash_key[key] = data
        self.hash_data[data] = key
