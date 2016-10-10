#!/usr/bin/env python
#
# Electrum - lightweight Bitcoin client
# Copyright (C) 2012 thomasv@ecdsa.org
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program. If not, see <http://www.gnu.org/licenses/>.


import os
import util
from lbrycrd import *

NULL_HASH = '0000000000000000000000000000000000000000000000000000000000000000'
MAX_TARGET = 0x0000FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF
HEADER_SIZE = 112
BLOCKS_PER_CHUNK = 96

HEADERS_URL = "https://s3.amazonaws.com/lbry-blockchain-headers/blockchain_headers_latest"

class Blockchain(util.PrintError):
    '''Manages blockchain headers and their verification'''

    def __init__(self, config, network):
        self.config = config
        self.network = network
        self.headers_url = HEADERS_URL
        self.local_height = 0
        self.set_local_height()
        self.retrieving_headers = False

    def height(self):
        return self.local_height

    def init(self):
        self.init_headers_file()
        self.set_local_height()
        self.print_error("%d blocks" % self.local_height)

    def verify_header(self, header, prev_header, bits, target):
        prev_hash = self.hash_header(prev_header)
        assert prev_hash == header.get('prev_block_hash'), "prev hash mismatch: %s vs %s" % (
        prev_hash, header.get('prev_block_hash'))
        assert bits == header.get('bits'), "bits mismatch: %s vs %s (hash: %s)" % (
        bits, header.get('bits'), self.hash_header(header))
        _pow_hash = self.pow_hash_header(header)
        assert int('0x' + _pow_hash, 16) <= target, "insufficient proof of work: %s vs target %s" % (
        int('0x' + _pow_hash, 16), target)

    def verify_chain(self, chain):
        first_header = chain[0]
        height = first_header['block_height']
        prev_header = self.read_header(height - 1)
        for header in chain:
            height = header['block_height']
            if self.read_header(height) is not None:
                bits, target = self.get_target(height, prev_header, header, self.config.get('chain'))
                self.verify_header(header, prev_header, bits, target)
            prev_header = header

    def verify_chunk(self, index, data):
        prev_header = None
        if index != 0:
            prev_header = self.read_header(index * BLOCKS_PER_CHUNK - 1)
        for i in range(BLOCKS_PER_CHUNK):
            raw_header = data[i * HEADER_SIZE:(i + 1) * HEADER_SIZE]
            header = self.deserialize_header(raw_header)
            bits, target = self.get_target(index * BLOCKS_PER_CHUNK + i, prev_header, header, self.config.get('chain'))
            if header is not None:
                self.verify_header(header, prev_header, bits, target)
            prev_header = header

    def get_block_hash(self, header):
        block_hash = header.get('prev_block_hash')
        if block_hash:
            return block_hash
        else:
            assert header.get('block_height') == 0
            return NULL_HASH

    def serialize_header(self, res):
        s = int_to_hex(res.get('version'), 4) \
            + rev_hex(self.get_block_hash(res)) \
            + rev_hex(res.get('merkle_root')) \
            + rev_hex(res.get('claim_trie_root')) \
            + int_to_hex(int(res.get('timestamp')), 4) \
            + int_to_hex(int(res.get('bits')), 4) \
            + int_to_hex(int(res.get('nonce')), 4)

        return s

    def deserialize_header(self, s):
        hex_to_int = lambda s: int('0x' + s[::-1].encode('hex'), 16)
        h = {}
        h['version'] = hex_to_int(s[0:4])
        h['prev_block_hash'] = hash_encode(s[4:36])
        h['merkle_root'] = hash_encode(s[36:68])
        h['claim_trie_root'] = hash_encode(s[68:100])
        h['timestamp'] = hex_to_int(s[100:104])
        h['bits'] = hex_to_int(s[104:108])
        h['nonce'] = hex_to_int(s[108:112])
        return h

    def hash_header(self, header):
        if header is None:
            return '0' * 64
        return hash_encode(Hash(self.serialize_header(header).decode('hex')))

    def pow_hash_header(self, header):
        if header is None:
            return '0' * 64
        return hash_encode(PoWHash(self.serialize_header(header).decode('hex')))

    def path(self):
        return os.path.join(self.config.path, 'blockchain_headers')

    def init_headers_file(self):
        filename = self.path()
        if os.path.exists(filename):
            return
        try:
            import urllib, socket
            socket.setdefaulttimeout(30)
            self.print_error("downloading ", self.headers_url)
            self.retrieving_headers = True
            try:
                urllib.urlretrieve(self.headers_url, filename)
            except:
                raise
            finally:
                self.retrieving_headers = False
            self.print_error("done.")
        except Exception:
            self.print_error("download failed. creating file", filename)
            open(filename, 'wb+').close()

    def save_chunk(self, index, chunk):
        filename = self.path()
        f = open(filename, 'rb+')
        f.seek(index * BLOCKS_PER_CHUNK * HEADER_SIZE)
        h = f.write(chunk)
        f.close()
        self.set_local_height()

    def save_header(self, header):
        data = self.serialize_header(header).decode('hex')
        assert len(data) == HEADER_SIZE, "Header is wrong size"
        height = header.get('block_height')
        filename = self.path()
        f = open(filename, 'rb+')
        f.seek(height * HEADER_SIZE)
        h = f.write(data)
        f.close()
        self.set_local_height()

    def set_local_height(self):
        name = self.path()
        if os.path.exists(name):
            h = os.path.getsize(name) / HEADER_SIZE - 1
            if self.local_height != h:
                self.local_height = h

    def read_header(self, block_height):
        name = self.path()
        if os.path.exists(name):
            f = open(name, 'rb')
            f.seek(block_height * HEADER_SIZE)
            h = f.read(HEADER_SIZE)
            f.close()
            if len(h) == HEADER_SIZE:
                h = self.deserialize_header(h)
                return h

    def get_target(self, index, first, last, chain='main'):
        # print_error("Get target for block ", index)
        if index == 0:
            return 0x1f00ffff, MAX_TARGET
        assert last is not None, "Last shouldn't be none"
        # bits to target
        bits = last.get('bits')
        # print_error("Last bits: ", bits)
        bitsN = (bits >> 24) & 0xff
        assert 0x03 <= bitsN <= 0x1f, "First part of bits should be in [0x03, 0x1d]"
        bitsBase = bits & 0xffffff
        assert 0x8000 <= bitsBase <= 0x7fffff, "Second part of bits should be in [0x8000, 0x7fffff]"
        target = bitsBase << (8 * (bitsN - 3))
        # new target
        nActualTimespan = last.get('timestamp') - first.get('timestamp')
        # regtest has target timespan of 1, so that blocks are quickly generated
        # otherwise , target is 2min 30 seconds 
        if chain == 'regtest':
            nTargetTimespan = 1
        else:
            nTargetTimespan = 150
        nModulatedTimespan = nTargetTimespan - (nActualTimespan - nTargetTimespan) / 8
        nMinTimespan = nTargetTimespan - (nTargetTimespan / 8)
        nMaxTimespan = nTargetTimespan + (nTargetTimespan / 2)
        nModulatedTimespan = nMinTimespan if nModulatedTimespan < nMinTimespan else nMaxTimespan
        new_target = target * nModulatedTimespan
        while new_target >= 2 ** 256:
            new_target -= 2 ** 256
        new_target = new_target / nModulatedTimespan
        new_target = min(MAX_TARGET, new_target)
        # convert new target to bits
        c = ("%064x" % new_target)
        c = c[2:]
        while c[:2] == '00' and len(c) > 6:
            c = c[2:]
        bitsN, bitsBase = len(c) / 2, int('0x' + c[:6], 16)
        if bitsBase >= 0x800000:
            bitsN += 1
            bitsBase >>= 8
        new_bits = bitsN << 24 | bitsBase
        # print_error("Calculated bits: ", new_bits)
        return new_bits, bitsBase << (8 * (bitsN - 3))

    def connect_header(self, chain, header):
        '''Builds a header chain until it connects.  Returns True if it has
        successfully connected, False if verification failed, otherwise the
        height of the next header needed.'''
        chain.append(header)  # Ordered by decreasing height
        height = header['block_height']
        if height > 0 and self.need_previous(header):
            return height - 1
        # The chain is complete so we can save it
        return self.save_chain(chain, height)

    def save_chain(self, chain, height):
        # Reverse to order by increasing height
        chain.reverse()
        try:
            self.verify_chain(chain)
            self.print_error("connected at height:", height)
            for header in chain:
                self.save_header(header)
            return True
        except BaseException as e:
            self.print_error(str(e))
            return False

    def need_previous(self, header):
        """Return True if we're missing the block before the one we just got"""
        previous_height = header['block_height'] - 1
        previous_header = self.read_header(previous_height)
        # Missing header, request it
        if not previous_header:
            return True
        # Does it connect to my chain?
        prev_hash = self.hash_header(previous_header)
        if prev_hash != header.get('prev_block_hash'):
            self.print_error("reorg")
            return True

    def connect_chunk(self, idx, hexdata):
        try:
            data = hexdata.decode('hex')
            self.verify_chunk(idx, data)
            self.print_error("validated chunk %d" % idx)
            self.save_chunk(idx, data)
            return idx + 1
        except BaseException as e:
            self.print_error('verify_chunk failed', str(e))
            return idx - 1
