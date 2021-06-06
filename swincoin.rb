=begin
    Swincoin: A Decentralized Peer-To-Peer Digital Currency (Cryptocurrency)
    Name: Karan Manoj Shah | Student ID: 103141481
    Unit: COS10009 Introduction To Programming
    Semester 1, 2021 | Swinburne University of Technology
=end

require "sinatra" # Used to start local server
require "faraday" # Used to query URLs (communicate with other nodes)
require "gosu" # Used for graphical user interface
require "openssl" # Used for generating large prime numbers
require "digest" # Used for generating SHA256 hashes
require "colorize" # Used to show colorful terminal outputs

# Declaring Constants
WIDTH = 800
HEIGHT = 500
COLOR_BLACK = 0xff_000000
COLOR_WHITE = 0xff_ffffff
COLOR_LIGHT_GREY = 0xff_cdcdcd
COLOR_DARK_GREY = 0xff_a9a9a9
URL = "http://127.0.0.1" # IP Address Of Device That Hosts The Nodes
FIRST_PORT = 1801
GENESIS_REWARD = 49985.0 # Number of Swincoins Mined When First User Created
MINER_REWARD = 15.0 # Reward To Swincoin Miners For Each Block Mined
NONCE_ZEROES = 5 # Proof-of-Work Complexity

# Defining Class Block
# Purpose: Record All The Blocks Of This Node's Blockchain Ledger
# Attributes: float amount, array key_public int signature, int timestamp, string prev_hash, string nonce, string hash, int payer, int payee, int miner
class Block
    attr_accessor :amount, :signature, :timestamp, :prev_hash, :nonce, :hash, :payer, :payee, :miner
    def initialize (amount, signature, timestamp, prev_hash, nonce, hash, payer, payee, miner)
        @amount = amount
        @signature = signature
        @timestamp = timestamp
        @prev_hash = prev_hash
        @nonce = nonce
        @hash = hash
        @payer = payer
        @payee = payee
        @miner = miner
    end
end
$blockchain = Array.new
$status = ""

# Defining Class Peers
# Purpose: Store Record Of All Peers In The Network
# Attributes: int port, string name, int key_public, node_type, float balance
class Peers
    attr_accessor :port, :name, :key_public, :node_type, :balance
    def initialize (port, name, key_public, node_type, balance)
        @port = port
        @name = name
        @key_public = key_public
        @node_type = node_type
        @balance = balance
    end
end
$peers = Array.new

# Defining Function generate_primes
# Purpose: Generate Two Very Large Prime Numbers
# Parameters: size (size of prime number in bits)
# Return: prime long int p, prime long int q
def generate_primes(size)
    # Generate two 12-bit prime numbers
    p = OpenSSL::BN::generate_prime(size).to_i
    q = OpenSSL::BN::generate_prime(size).to_i
    # Ensure the two prime numbers are different
    loop do
        break if p != q
        q = OpenSSL::BN::generate_prime(size).to_i
    end
    return [p,q]
end

# Defining Funciton generate_rsa_keys
# Purpose: Generate Public and Private Keys Using RSA Cryptography
# Parameters: primary long int p, primary long int q
# Return: int key_public, long int key_private, long int n
def generate_rsa_keys(p, q)
    # Find "n", the product of two primes
    n = p * q
    # Calculate Euler's Totient For The Two Primes
    eulers_totient = (p - 1) * (q - 1)
    # Find Public Key "e" such that 1 < e < totient, e is coprime to totient
    key_public = 2
    loop do
        break if (key_public.gcd(eulers_totient) == 1)
        key_public += 1
    end
    # Find Private Key "d" such that e * d * mod(totient) = 1
    key_private = 1
    loop do
        key_private += 1
        break if ((key_public * key_private) % eulers_totient == 1)
    end
    # Public Key = (e,n), Private Key = (d,n)
    return [key_public, key_private, n]
end

# Defining function sign_block
# Purpose: Generate Ciphertext Using Node's RSA Private Key to Authenticate Block
# Parameters: array key_private, Time timestamp
# Return: int signature
def sign_block(key_private, timestamp)
    # RSA Encryption (Formula: C = M^d mod n)
    timestamp = timestamp.to_i % key_private[1].to_i
    signature = timestamp.to_bn.mod_exp(key_private[0],key_private[1])
    return signature
end

# Defining Function validate_signature
# Purpose: Validates RSA signature on a block against its RSA public key
# Parameters: array key_public, int signature, Time timestamp
# Return: boolean is_valid
def validate_signature(key_public, signature, timestamp)
    # RSA Decryption (Formula: M = C^e mod n)
    timestamp = timestamp.to_i % key_public[1].to_i
    signature = signature.to_i
    decipher = signature.to_bn.mod_exp(key_public[0].to_i,key_public[1].to_i)
    return true if (decipher == timestamp)
    return false
end

# Defining Function get_node_details
# Purpose: Gets important node details to share with peers on network
# Return: int port, string name, node_type
def set_node_details
    print "Enter your name: "
    name = gets.chomp.to_s
    node_type = 2
    port = FIRST_PORT.to_i
    loop do
        begin
            Faraday.get("#{URL}:#{port}").body # Port Used By Another Peer
            port += 1 # Check Next Port
        rescue Faraday::ConnectionFailed # Port Is Vacant
            return port, name, node_type
        rescue Exception => e
            return e
        end
    end
end

# Defining Procedure initialize_server
# Purpose: Use To Configure Sinatra Environment Variables and Start Server
# Parameters: int port
def initialize_server(port)
    set :port, port # Specify Port For Sinatra Server
    set :bind, "0.0.0.0" # Allow Ping From External Devices
    set :environment, :production # Allow External Nodes To Query Websocket
    set :run, true # Start Sinatra Server
end

# Defining Procedure set_routes
# Purpose: Establish GET/POST Routes On Node's Websocket For P2P Communication
# Parameters: int my_port, string name, int node_type, array keys
def set_routes(my_port, name, node_type, keys)
    # Give Access To This Node's Name
    get "/peer_name" do
        return name
    end
    # Give Access To This Node's Type (Client/Miner)
    get "/peer_type" do
        return node_type.to_s
    end
    # Give Access To This Node's Public Key For Validation & Handshake
    get "/peer_key_public" do
        return "#{keys[0]},#{keys[2]}"
    end
    # Give Access To This Node's Discovered Peers
    get "/peer_peers" do
        peer_ports = ""
        $peers.length.times do |i|
            peer_ports +=  "," if (i != 0)
            peer_ports +=  $peers[i].port.to_s
        end
        return peer_ports
    end
    # Another Peer Requests Handshake
    post "/peer_handshake" do
        port = params["port"].chomp.to_i
        signature = params["signature"].chomp.to_i
        timestamp = params["timestamp"].chomp.to_i
        # Handshake Only With Undiscovered Peers
        if (search_peers_by_port(port) == -1)
            key_public = Faraday.get("#{URL}:#{port}/peer_key_public").body
            key_public = key_public.split(",") # Convert String To Array
            # Validate Node's Authenticity Using RSA Decryption
            if (validate_signature(key_public, signature, timestamp))
                add_peer(port)
                handshake_peer(my_port, port, [keys[1], keys[2]])
            end
        end
    end
    # Request To Mine A Block
    post "/mine_block" do
        amount = params["amount"].to_s
        payer = params["payer"].to_s
        timestamp = params["timestamp"].to_s
        signature = params["signature"].to_s
        prev_hash = params["prev_hash"].to_s
        payee = params["payee"].to_s
        miner = my_port.to_s

        payer_peer = search_peers_by_port(payer)
        if (payer_peer != -1 && payer_peer.node_type != 3) # Validate if peer exists and is not rogue
            mine(amount, payer, payee, miner, timestamp, signature, prev_hash)
        else
            puts "Denied mining request from rogue node".red
            $status = "Denied mining request from rogue node"
        end
    end
    # Recieve A Mined Block
    post "/block_mined" do
        amount = params["amount"].to_s
        payer = params["payer"].to_s
        payee = params["payee"].to_s
        miner = params["miner"].to_s
        timestamp = params["timestamp"].to_s
        signature = params["signature"].to_s
        prev_hash = params["prev_hash"].to_s
        nonce = params["nonce"].to_s
        # Add Block If Not Already Mined
        block_exists = check_if_block_exists(miner.to_i, timestamp.chomp.to_i)
        add_block(amount, payer, payee, miner, timestamp, signature, prev_hash, nonce, true) if (!block_exists)
    end
    # Peer Sent A Mined Block
    post "/broadcast_block" do
        amount = params["amount"].to_f
        signature = params["signature"].to_s
        timestamp = params["timestamp"].to_i
        prev_hash = params["prev_hash"].to_s
        nonce = params["nonce"].to_s
        hash = params["hash"].to_s
        payer = params["payer"].to_i
        payee = params["payee"].to_i
        miner = params["miner"].to_i

        payer_peer = search_peers_by_port(payer)
        if (prev_hash == "0000000000000000000000000000000000000000000000000000000000000000" && $blockchain.length > 0)
            # Genesis Node is being shared with everyone, this node does not require as it already has a chain. Ignore.
        else
            if (payer_peer != -1 && payer_peer.node_type != 3) # Validate if peer exists and is not rogue
                is_valid = validate_block(amount, signature, timestamp, prev_hash, nonce, hash, payer, payee, miner)
                if (is_valid)
                    puts "VALIDATED OK".green
                    add_block(amount, payer, payee, miner, timestamp, signature, prev_hash, nonce, false)
                end
            else
                puts "Denied block broadcast from rogue node".red
                $status = "Denied block broadcast from rogue node"
            end
        end
    end
    # Broadcast First Block (Genesis Block) To Peers
    post "/genesis" do
        broadcast_block($blockchain[0])
    end
end

# Defining Procedure handshake_peer
# Purpose: Sends Discovery Requests To Peers On Network
# Parameters: int port, int to, array key_private
def handshake_peer (port, to, key_private)
    timestamp = Time.now.to_i
    signature = sign_block(key_private, timestamp)
    Faraday.post("#{URL}:#{to}/peer_handshake", port: port, signature: signature, timestamp: timestamp)
end

# Defining Procedure add_peer
# Purpose: Add A Peer To The Peers Record
# Parameters: int port
def add_peer(port)
    name = Faraday.get("#{URL}:#{port}/peer_name").body.to_s.chomp
    key_public = Faraday.get("#{URL}:#{port}/peer_key_public").body.to_s.chomp
    key_public = key_public.split(",")
    node_type = Faraday.get("#{URL}:#{port}/peer_type").body.chomp.to_i
    new_peer = Peers.new(port.to_i, name, key_public, node_type, 0.0)
    $peers << new_peer
    puts "Added peer #{port}".light_blue
    $status = "Added peer #{port}"
end

# Defining Procedure discover_peers
# Purpose: Find Undiscovered Peers On Network & Handshake With Them
# Parameters: int port, array key_private
def discover_peers(port, key_private)
    handshake_peer(port, FIRST_PORT, key_private) # Handshake Genesis Peer
    i = 0
    peers = Array.new # Array To Store Ports Of Discovered Peers
    $peers.length.times do |i| # Store Your Discovered Peers
        peers << $peers[i].port.to_s
    end
    while (i < peers.length) # Store Others Discovered Peers
        their_peers = Faraday.get("#{URL}:#{peers[i]}/peer_peers").body.to_s.chomp
        their_peers = their_peers.split(",")
        their_peers.length.times do |j|
            search_result = 0
            peers.length.times do |k|
                search_result = -1 if (their_peers[j] == peers[k])
            end
            peers << their_peers[j] if (search_result != -1)
        end
        i += 1
    end
    # Handshake Newly Discovered Peers
    i = 0
    peers.length.times do |i|
        handshake_peer(port, peers[i], key_private) if (search_peers_by_port(peers[i]) == -1)
    end
end

# Defining Function search_peers_by_port
# Purpose: Return a Peer record reference if found, else return -1
# Parameters: int port
# Return: Peer peer
def search_peers_by_port (port)
    $peers.length.times do |i|
        return $peers[i] if ($peers[i].port == port.to_i)
    end
    return -1
end

# Defining function new_block
# Purpose: Transfer Swincoins to another node
# Parameters: float amount, int payer, int payee, array key_private
def new_block(amount, payer, payee, key_private)
    timestamp = Time.now.to_i
    signature = sign_block(key_private, Time.now)
    if ($blockchain.length == 0)
        prev_hash = "0000000000000000000000000000000000000000000000000000000000000000" # If First Block, No Previous Hash So 64 Zeroes Default
    else
        prev_hash = $blockchain[$blockchain.length-1].hash # Hash Of Previous Block
    end
    blob = amount.to_s + payer.to_s + payee.to_s + timestamp.to_s + prev_hash.to_s
    begin
        if ($blockchain.length > 0) # Send To All Miners If Not Genesis Block
            $peers.length.times do |i|
                Thread.new { Faraday.post("#{URL}:#{$peers[i].port}/mine_block", amount: amount, payer: payer, payee: payee, timestamp: timestamp, signature: signature, prev_hash: prev_hash) if ($peers[i].port != payer) }
            end
        else # Send To First Port If Genesis Block
            Faraday.post("#{URL}:1801/mine_block", amount: amount, payer: payer, payee: payee, timestamp: timestamp, signature: signature, prev_hash: prev_hash)
        end
    rescue
        # Miner Never Sent Response (Do Nothing)
    end
end

# Defining procedure mine
# Purpose: Generate Proof-Of-Work and Send Nonce to Client Node
# Parameters: float amount, int payer, int payee, int miner, int timestamp, int signature, string prev_hash
def mine(amount, payer, payee, miner, timestamp, signature, prev_hash)
    blob = amount.to_s + payer.to_s + payee.to_s + miner.to_s + timestamp.to_s + signature.to_s + prev_hash.to_s
    nonce = find_nonce(blob)
    Faraday.post("#{URL}:#{payer}/block_mined", amount: amount, payer: payer, payee: payee, miner: miner, timestamp: timestamp, signature: signature, prev_hash: prev_hash, nonce: nonce)
end

# Defining function find_nonce
# Purpose: Generate A Nonce Which, When Coupled With Blob, Gives A Hash Starting With NONCE_ZEROES
# Parameters: string blob
# Returns: string nonce
def find_nonce(blob)
    $status = "Mining Started"
    puts "Mining Started".blue
    start_time = Time.now
    nonce = "0"
    loop do
        nonce = rand(0..9999999999).to_s
        hash = Digest::SHA256.new.hexdigest(blob + nonce)
        break if (hash.start_with?("0" * NONCE_ZEROES))
    end
    end_time = Time.now
    $status = "Mining Ends in #{end_time - start_time} seconds"
    puts "Mining Ends in #{end_time - start_time} seconds".blue
    return nonce
end

# Defining procedure add_block
# Purpose: Add a New Block to the Node's Blockchain, then Broadcast it to Peers
# Parameters: float amount, int payer, int payee, int miner, int timestamp, int signature, string prev_hash, string nonce, boolean broadcast
def add_block(amount, payer, payee, miner, timestamp, signature, prev_hash, nonce, broadcast)
    hash = Digest::SHA256.new.hexdigest(amount.to_s + payer.to_s + payee.to_s + miner.to_s + timestamp.to_s + signature.to_s + prev_hash.to_s + nonce.to_s)
    if (hash.start_with?("0" * NONCE_ZEROES)) # Hash Is Valid
        block = Block.new(amount.to_f, signature.to_i, timestamp.to_i, prev_hash.to_s, nonce.to_i, hash.to_s, payer.to_i, payee.to_i, miner.to_i)
        $blockchain << block
        broadcast_block(block) if (broadcast)
        puts $blockchain.length.to_s.green
        Thread.new { calc_net_worth } # Calculates net worth of all peers
    else
        puts "Hash #{hash} Does Not Match Requirements! BLACKLISTING PEER WITH PORT #{payer}".red
        $status = "Hash #{hash} Does Not Match Requirements! BLACKLISTING PEER WITH PORT #{payer}"
        peer = search_peers_by_port(payer)
        peer.node_type = 3 if (peer != -1)
    end
end

# Defining procedure broadcast_block
# Purpose: Share New Block Details With All Peers
# Parameters: Block block
def broadcast_block(block)
    $peers.length.times do |i|
        Faraday.post("#{URL}:#{$peers[i].port}/broadcast_block", amount: block.amount, signature: block.signature, timestamp: block.timestamp, prev_hash: block.prev_hash, nonce: block.nonce, hash: block.hash, payer: block.payer, payee: block.payee, miner: block.miner) if ($peers[i].port.to_s.chomp != block.payer.to_s.chomp)
    end
end

# Defining function validate_block
# Purpose: Validate new transaction blocks sent from peers before accepting
# Parameters: float amount, int signature, int timestamp, string prev_hash, string nonce, string hash, int payer, int payee, int miner
# Returns: boolean (true=validate/false=invalid)
def validate_block(amount, signature, timestamp, prev_hash, nonce, hash, payer, payee, miner)
    puts "Validating Block From #{payer}...".blue
    error = ""
    if (hash.start_with?("0" * NONCE_ZEROES))
        peer = search_peers_by_port(payer)
        if (peer != -1)
            if (validate_signature(peer.key_public, signature, timestamp))
                    if $blockchain.length == 0
                        return true
                    else
                        if (peer.balance.to_f >= amount.to_f)
                            prev_block = $blockchain[$blockchain.length - 1]
                            prev_block_hash = Digest::SHA256.new.hexdigest(prev_block.amount.to_s + prev_block.payer.to_s + prev_block.payee.to_s + prev_block.miner.to_s + prev_block.timestamp.to_s + prev_block.signature.to_s + prev_block.prev_hash.to_s + prev_block.nonce.to_s)
                            if (prev_hash == prev_block_hash)
                                return true
                            else
                                error = "Previous Hash = #{prev_hash}\nThis Block Has #{prev_block_hash}, Not Matching."
                            end
                        else
                            error = "Payer doesn't have enough Swincoins."
                        end
                    end 
            else
                error = "Wrong Signature."
            end
        else
            error = "Peer Not Found."
        end
    else
        error = "Hash #{hash} Not Nonced, no Proof of Work Found."
    end
    # If Payer Sends Invalid Block, Add Them To Rogue List
    puts "INVALID BLOCK... BLACKLISTING PEER #{payer}".red
    puts error.red
    $status = "INVALID BLOCK... BLACKLISTING PEER #{payer} because #{error}"
    peer = search_peers_by_port(payer)
    peer.node_type = 3 if (peer != -1)
    return false
end

# Defining procedure calc_net_worth
# Purpose: Calculates the net worth of all peers by adding last block's details
def calc_net_worth
    $peers.length.times do |i|
        $peers[i].balance = 0.0
    end
    $blockchain.length.times do |i|
        if (i == 0)
            genesis_node = search_peers_by_port($blockchain[i].miner.to_i)
            genesis_node.balance = GENESIS_REWARD + MINER_REWARD
        else
            payer = search_peers_by_port($blockchain[i].payer.to_i)
            payee = search_peers_by_port($blockchain[i].payee.to_i)
            miner = search_peers_by_port($blockchain[i].miner.to_i)
            payer.balance = payer.balance - $blockchain[i].amount.to_f
            payee.balance = payee.balance + $blockchain[i].amount.to_f
            miner.balance = miner.balance + MINER_REWARD
        end
    end
    $peers.length.times do |i|
        puts ($peers[i].name.to_s + " " + $peers[i].port.to_s + " " + $peers[i].balance.to_s).red
    end
end

# Defining procedure get_crypto_stats
# Purpose: Get crypto stats of a specified node
# Parameters: int port
# Return: array stats (0: received transactions, 1: generated transactions, 2: no of mined blocks)
def get_crypto_stats(port)
    r = 0 # Received
    g = 0 # Generated
    m = 0 # Mined
    $blockchain.length.times do |i|
        block = $blockchain[i]
        r +=1 if (block.payee == port)
        g +=1 if (block.payer == port)
        m +=1 if (block.miner == port)
    end
    return [r, g, m]
end

# Defining function check_if_block_exists
# Purpose: Checks if a block has already been mined by another miner
# Parameters: int miner, int timestamp
# Returns: boolean block_exists
def check_if_block_exists(miner, timestamp)
    block_exists = false
    winning_miner = nil
    $blockchain.length.times do |i|
        ts = $blockchain[i].timestamp
        block_exists = true if ts == timestamp
        winning_miner = $blockchain[i].miner
        break if block_exists
    end
    if block_exists
        $status = "Miner #{miner} is late, block already mined by #{winning_miner}"
        puts "Miner #{miner} is late, block already mined by #{winning_miner}".red
    end
    return block_exists
end

# Defining procedure export_blockchain
# Purpose: Save This Node's Blockchain To A Text File
def export_blockchain(my_port)
    puts "Exporting Blockchain...".blue
    $status = "Exporting Blockchain..."
    file = File.new("#{my_port}_blockchain.txt", "w")
    $blockchain.length.times do |i|
        file.puts "From: #{$blockchain[i].payer}"
        file.puts "To: #{$blockchain[i].payee}"
        file.puts "Amount: #{$blockchain[i].amount}"
        file.puts "Mined By: #{$blockchain[i].miner}"
        file.puts "Previous Block Hash: #{$blockchain[i].prev_hash}"
        file.puts "Block Hash: #{$blockchain[i].hash}"
        file.puts "Nonce: #{$blockchain[i].nonce}"
        file.puts "------------------------------------------------------------------------------------------------------------------------"
    end
    file.close
    puts "Exported Blockchain".blue
    $status = "Exported Blockchain"
end

# Defining procedure transfer_swincoin
# Purpose: Perform A Transaction Of Swincoin Between Two Nodes
# Parameters: float amount, int payer, int payee, array key_private
def transfer_swincoin(amount, payer, payee, key_private)
    payer_peer = search_peers_by_port(payee)
    if (payer_peer != -1)
        new_block(amount, payer, payee, key_private)
    else
        puts "Transaction failed. The payee port does not exist!".red
        $status = "Transaction failed. The payee port does not exist!"
    end
end

# Defining Class Interface (Subclass of Class Gosu::Window)
# Purpose: Graphical User Interface
class Interface < Gosu::Window
    attr_accessor :my_port, :key_public, :key_private

    # Configure GUI Window, Initialize Instance Variables
    def initialize(my_port, key_public, key_private)
        super WIDTH, HEIGHT
        self.caption = "Swincoin"
        @my_port = my_port
        @key_public = key_public
        @key_private = key_private
        @heading_font = Gosu::Font.new(self, Gosu::default_font_name, 35)
        @subheading_font = Gosu::Font.new(self, Gosu::default_font_name, 22)
        @content_font = Gosu::Font.new(self, Gosu::default_font_name, 18)
        @small_font = Gosu::Font.new(self, Gosu::default_font_name, 15)
        self.text_input = Gosu::TextInput.new
        self.text_input.text = "Amount,Port"
    end

    # Draw Elements On GUI Window
    def draw
        draw_rect(0, 0, WIDTH, 50, COLOR_BLACK, 0) # Header Background
        draw_rect(WIDTH-300, 50, 300, HEIGHT, COLOR_LIGHT_GREY, 1) # Action Panel
        @heading_font.draw_text("Swincoin", 350, 9, 1, 1.0, 1.0, COLOR_WHITE, mode=:default) # Header Text
        draw_info(mouse_x, mouse_y)
        draw_transaction_box(mouse_x, mouse_y)
        draw_peers
        # Footer
        draw_rect(0,HEIGHT-32,WIDTH,32,COLOR_BLACK,2)
        @content_font.draw_text("Last Action: #{$status}", 10, HEIGHT-22, 2, 1.0, 1.0, COLOR_WHITE, mode=:default)
    end

    # Draw All Peers In A Circular Shape
    def draw_peers
        draw_rect(0, 50, WIDTH-300, HEIGHT, COLOR_WHITE, 0)
        $peers.length.times do |i|
            draw_peer(i, 200, 100) if (i == 0)
            draw_peer(i, 50, 200) if (i == 1)
            draw_peer(i, 50, 300) if (i == 2)
            draw_peer(i, 200, 400) if (i == 3)
            draw_peer(i, 350, 300) if (i == 4)
            draw_peer(i, 350, 200) if (i == 5)
        end
    end

    # Draw A Specified Peer With Details On Specified Coordinates
    def draw_peer(peer_index,x,y)
        c = Circle.new(10, 0, 255, 0) if ($peers[peer_index].node_type == 2)
        c = Circle.new(10, 255, 0, 0) if ($peers[peer_index].node_type == 3)
        peer = Gosu::Image.new(c, false)
        peer.draw(x, y-3, z=2)
        @small_font.draw_text("Port: #{$peers[peer_index].port}", x-15, y+15, 2, 1.0, 1.0, COLOR_BLACK, mode=:default)
        @small_font.draw_text("Name: #{$peers[peer_index].name}", x-15, y+30, 2, 1.0, 1.0, COLOR_BLACK, mode=:default)
        @small_font.draw_text("Balance: #{$peers[peer_index].balance}", x-15, y+45, 2, 1.0, 1.0, COLOR_BLACK, mode=:default)
        draw_rect(x-1, y-4, 22, 22, COLOR_DARK_GREY, 1) if ($peers[peer_index].port == @my_port)
    end

    # Shows Key Stats Regarding The Blockchain
    def draw_info(mouse_x, mouse_y)
        # Network Info
        @content_font.draw_text("Number of peers: #{$peers.length}", WIDTH-280, 60, 2, 1.0, 1.0, COLOR_BLACK, mode=:default)
        coins_mined = $blockchain.length * MINER_REWARD
        coins_mined += GENESIS_REWARD if coins_mined > 0
        @content_font.draw_text("Swincoins Mined: #{coins_mined}", WIDTH-280, 80, 2, 1.0, 1.0, COLOR_BLACK, mode=:default)
        @content_font.draw_text("No. of Blocks: #{$blockchain.length}", WIDTH-280, 100, 2, 1.0, 1.0, COLOR_BLACK, mode=:default)
        # Export Blockcain Button
        if (mouse_x > 520 and mouse_x < 690) and (mouse_y > 120 and mouse_y < 150)
            draw_rect(WIDTH-280, 120, 170, 30, COLOR_DARK_GREY, 1)
        else
            draw_rect(WIDTH-280, 120, 170, 30, COLOR_BLACK, 1)
        end
        @content_font.draw_text("Export My Blockchain", WIDTH-275, 125, 2, 1.0, 1.0, COLOR_WHITE, mode=:default)
        draw_line(WIDTH-300, 160, COLOR_BLACK, WIDTH, 160, COLOR_BLACK, 1)
        # Node Info
        @subheading_font.draw_text("About This Node", WIDTH-280, 305, 1, 1.0, 1.0, COLOR_BLACK, mode=:default)
        @content_font.draw_text("Port: #{@my_port}", WIDTH-280, 330, 1, 1.0, 1.0, COLOR_BLACK, mode=:default)
        my_node = search_peers_by_port(@my_port)
        stats = get_crypto_stats(@my_port.to_i)
        @content_font.draw_text("Name: #{my_node.name}", WIDTH-170, 330, 1, 1.0, 1.0, COLOR_BLACK, mode=:default) if (my_node != -1)
        @content_font.draw_text("Transactions Received: #{stats[0]}", WIDTH-280, 350, 1, 1.0, 1.0, COLOR_BLACK, mode=:default)
        @content_font.draw_text("Transactions Generated: #{stats[1]}", WIDTH-280, 370, 1, 1.0, 1.0, COLOR_BLACK, mode=:default)
        @content_font.draw_text("Blocks Mined: #{stats[2]}", WIDTH-280, 390, 1, 1.0, 1.0, COLOR_BLACK, mode=:default)
        @content_font.draw_text("Balance: #{my_node.balance}", WIDTH-280, 410, 1, 1.0, 1.0, COLOR_BLACK, mode=:default) if (my_node != -1)
        @content_font.draw_text("RSA Pub Key: #{@key_public[0]},#{@key_public[1]}", WIDTH-280, 430, 1, 1.0, 1.0, COLOR_BLACK, mode=:default)
        @content_font.draw_text("RSA Secret Key: #{@key_private[0]},#{@key_private[1]}", WIDTH-280, 450, 1, 1.0, 1.0, COLOR_BLACK, mode=:default)
    end

    def draw_transaction_box(mouse_x, mouse_y)
        @subheading_font.draw_text("Transfer Swincoins", WIDTH-280, 170, 1, 1.0, 1.0, COLOR_BLACK, mode=:default)
        # Textbox + Placeholder
        draw_rect(WIDTH-280, 200, 200, 30, COLOR_WHITE, 1)
        if (self.text_input.text != "Amount,Port")
            @content_font.draw_text(self.text_input.text, WIDTH-278, 207, 2, 1.0, 1.0, COLOR_BLACK, mode=:default)
        else
            @content_font.draw_text(self.text_input.text, WIDTH-278, 207, 2, 1.0, 1.0, COLOR_DARK_GREY, mode=:default)
        end
        # Transfer Button
        if (self.text_input.text.to_s.chomp.match(/^[\d]+[.][\d]+,18\d\d$/))
            if (mouse_x > WIDTH-280 and mouse_x < 720) and (mouse_y > 230 and mouse_y < 260)
                draw_rect(WIDTH-280, 230, 200, 30, COLOR_DARK_GREY, 1)
            else
                draw_rect(WIDTH-280, 230, 200, 30, COLOR_BLACK, 1)
            end
        else
            draw_rect(WIDTH-280, 230, 200, 30, COLOR_DARK_GREY, 1)
        end
        @content_font.draw_text("Transfer", WIDTH-210, 237, 2, 1.0, 1.0, COLOR_WHITE)
        @small_font.draw_text("Amount as float + comma (no spaces) +\n4 digit port starting with '18'", WIDTH-280, 265, 1, 1.0, 1.0, COLOR_BLACK, mode=:default)
        draw_line(WIDTH-300, 300, COLOR_BLACK, WIDTH, 300, COLOR_BLACK, 1)
    end

    # Detect Keyboard/Mouse Input
    def button_down(id)
        if (id == Gosu::MsLeft)
            # Export Blockchain Button
            export_blockchain(@my_port) if (mouse_x > 520 and mouse_x < 690) and (mouse_y > 120 and mouse_y < 150)
            # Clear Textbox Placeholder Text
            if (mouse_x > 520 and mouse_x < 720) and (mouse_y > 190 and mouse_y < 220)
                self.text_input.text = "" if (self.text_input.text == "Amount,Port")
            else
                self.text_input.text = "Amount,Port" if (self.text_input.text == "")
            end
            # Transfer Button
            if (mouse_x > WIDTH-280 and mouse_x < 720) and (mouse_y > 230 and mouse_y < 260) and (self.text_input.text.to_s.chomp.match(/^[\d]+[.][\d]+,18\d\d$/))
                transaction_details = self.text_input.text.to_s.chomp.split(',')
                amount = transaction_details[0].to_f
                payer = @my_port.to_i
                payee = transaction_details[1].to_i
                self.text_input.text = "Amount,Port"
                transfer_swincoin(amount, @my_port, payee, @key_private)
            end
        end
    end
end

# Defining Class Circle
# Purpose: Draw Coloured Circles On GUI
class Circle
    attr_reader :columns, :rows

    def initialize(radius, colorR, colorG, colorB)
        @columns = @rows = radius * 2
        lower_half = (0...radius).map do |y|
            x = Math.sqrt(radius**2 - y**2).round
            right_half = "#{"#{colorR.chr}" * x}#{"#{0.chr}" * (radius - x)}"
            "#{right_half.reverse}#{right_half}"
        end.join
        blob0 = lower_half.reverse + lower_half
        blob0.gsub!(/./) { |alpha| "#{colorR.chr}#{colorG.chr}#{colorB.chr}#{alpha}"}
        lower_half = (0...radius).map do |y|
            x = Math.sqrt(radius**2 - y**2).round
            right_half = "#{"#{colorG.chr}" * x}#{"#{0.chr}" * (radius - x)}"
            "#{right_half.reverse}#{right_half}"
        end.join
        blob1 = lower_half.reverse + lower_half
        blob1.gsub!(/./) { |alpha| "#{colorR.chr}#{colorG.chr}#{colorB.chr}#{alpha}"}
        lower_half = (0...radius).map do |y|
            x = Math.sqrt(radius**2 - y**2).round
            right_half = "#{"#{colorB.chr}" * x}#{"#{0.chr}" * (radius - x)}"
            "#{right_half.reverse}#{right_half}"
        end.join
        blob2 = lower_half.reverse + lower_half
        blob2.gsub!(/./) { |alpha| "#{colorR.chr}#{colorG.chr}#{colorB.chr}#{alpha}"}
        if colorB > 0
            @blob = blob2
        elsif colorG > 0
            @blob = blob1
        else
            @blob = blob0
        end
    end

    def to_blob
        @blob
    end
end

# Defining Procedure main
# Purpose: Initialize Node, Connect To Network, Start GUI
def main
    # Generate RSA Keys
    primes = generate_primes(12)
    keys = generate_rsa_keys(primes[0], primes[1])
    key_public = [keys[0], keys[2]]
    key_private = [keys[1], keys[2]]

    # Establish Node Server
    node_details = set_node_details
    port = node_details[0]
    name = node_details[1]
    node_type = node_details[2]
    if (node_details.length == 3) # Node Details Returns Required Values
        initialize_server(port)
        set_routes(port, name, node_type, keys)
    else # Node Details Returns An Error
        puts "Error: #{node_details}"
        $status = "Error: #{node_details}"
    end

    # Discover Peers Parallely To Other Crypto Fucntions (Hence New Thread)
    Thread.new {
        discover_peers(port, key_private)
        new_block(GENESIS_REWARD, 1801, port, key_private) if (port == 1801)
        begin
            Faraday.post("#{URL}:1801/genesis") if (port != 1801) # Get First Block in Blockchain From Genesis Node
        rescue
            # Node Responts With No Data
        end
    }

    Thread.new { Interface.new(port, key_public, key_private).show }
end

main if __FILE__ == $0