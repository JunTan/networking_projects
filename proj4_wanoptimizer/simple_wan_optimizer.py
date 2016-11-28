import wan_optimizer
import tcp_packet
import utils

class WanOptimizer(wan_optimizer.BaseWanOptimizer):
    """ WAN Optimizer that divides data into fixed-size blocks.

    This WAN optimizer should implement part 1 of project 4.
    """

    # Size of blocks to store, and send only the hash when the block has been
    # sent previously
    BLOCK_SIZE = 8000
    hash_key = {}
    hash_data = {}

    def __init__(self):
        wan_optimizer.BaseWanOptimizer.__init__(self)
        # Add any code that you like here (but do not add any constructor arguments).
        self.src_dest_buffer = {}
        return

    def receive(self, packet):
        """ Handles receiving a packet.

        Right now, this function simply forwards packets to clients (if a packet
        is destined to one of the directly connected clients), or otherwise sends
        packets across the WAN. You should change this function to implement the
        functionality described in part 1.  You are welcome to implement private
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
            if (src, dest) not in self.src_dest_buffer:
                self.src_dest_buffer[(src, dest)] = ""
            
            if not packet.is_raw_data:
                # Decode the hash, replace the hash with actual data
                data = self.hash_key[packet.payload]
                #packet = tcp_packet.Packet(src, dest, is_raw_data, is_fin, payload)
            else:
                # Compute the hash and store the mapping
                data = packet.payload
                self.create_mapping(data, src, dest)
            '''
            packet = tcp_packet.Packet(src, dest, True, is_fin, data)
            self.send(packet, self.address_to_port[packet.dest])
            '''
            self.src_dest_buffer[(src, dest)] += data

            buff = self.src_dest_buffer[(src, dest)]
            if len(buff) >= self.BLOCK_SIZE:
                data = buff[ :self.BLOCK_SIZE]
                self.src_dest_buffer[(src, dest)] = buff[self.BLOCK_SIZE: ]
                while (data):
                    payload = data[ :utils.MAX_PACKET_SIZE]
                    packet = tcp_packet.Packet(src, dest, True, False, payload)
                    print "size data to client######################: \n", len(payload)
                    self.send(packet, self.address_to_port[packet.dest])
                    data = data[utils.MAX_PACKET_SIZE: ]
            if is_fin:
                data = self.src_dest_buffer[(src, dest)]
                while (True):
                    payload = data[ :utils.MAX_PACKET_SIZE]
                    #print "data to client[Fin]#####################: \n", payload
                    if not data:
                        packet = tcp_packet.Packet(src, dest, True, True, payload)
                        self.send(packet, self.address_to_port[packet.dest])
                        self.src_dest_buffer[(src, dest)] = ""
                        break

                    packet = tcp_packet.Packet(src, dest, True, False, payload)
                    self.send(packet, self.address_to_port[packet.dest])
                    data = data[utils.MAX_PACKET_SIZE: ]
            
        else:
            # The packet must be destined to a host connected to the other middlebox
            # so send it across the WAN.
            src = packet.src
            dest = packet.dest
            data = packet.payload
            is_fin = packet.is_fin

            if not packet.is_raw_data:
                self.send(packet, self.wan_port)
                return

            # Add to the buffer
            if (src, dest) not in self.src_dest_buffer:
                self.src_dest_buffer[(src, dest)] = ""
            self.src_dest_buffer[(src, dest)] += data

            # Send the data only if the size of the data is greater than the
            # block size or the packect has is_fin = True
            buff = self.src_dest_buffer[(src, dest)]
            if len(buff) >= self.BLOCK_SIZE:
                data = buff[ :self.BLOCK_SIZE]
                self.src_dest_buffer[(src, dest)] = buff[self.BLOCK_SIZE: ]

                # Hash the data if it is sent the first time, and store the mapping
                while (data):
                    payload = data[ :utils.MAX_PACKET_SIZE]
                    if payload not in self.hash_key.values():
                        self.create_mapping(payload, src, dest)
                        is_raw_data = True
                    else:
                        payload = self.hash_data[payload]
                        is_raw_data = False
                    packet = tcp_packet.Packet(src, dest, is_raw_data, False, payload)
                    print "size data to WAN####################: \n", len(payload)
                    self.send(packet, self.wan_port)
                    data = data[utils.MAX_PACKET_SIZE: ]
            # If the packet has is_fin = True, send the remaing data
            if is_fin:
                data = self.src_dest_buffer[(src, dest)]
                while (True):
                    payload = data[ :utils.MAX_PACKET_SIZE]
                    if payload not in self.hash_key.values():
                        self.create_mapping(payload, src, dest)
                        is_raw_data = True
                    else:
                        payload = self.hash_data[payload]
                        is_raw_data = False
                    #print "data to WAN[Fin]###################: \n", payload
                    if not data:
                        packet = tcp_packet.Packet(src, dest, is_raw_data, True, payload)
                        self.send(packet, self.wan_port)
                        self.src_dest_buffer[(src, dest)] = ""
                        break
                   
                    packet = tcp_packet.Packet(src, dest, is_raw_data, False, payload)
                    self.send(packet, self.wan_port)
                    data = data[utils.MAX_PACKET_SIZE: ]

    def create_mapping(self, data, src, dest):
        key = utils.get_hash(data)
        self.hash_key[key] = data
        self.hash_data[data] = key

