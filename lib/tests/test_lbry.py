import unittest
import binascii
from lib import lbrycrd
from lib import claims 

def get_powhash(input_str):
    out=lbrycrd.PoWHash(input_str)
    hex_out = out.encode('hex_codec')
    # need to reformat to little endian int 
    out_str=''
    for i in range(64,0,-2):
        out_str+=hex_out[i-2:i]
    return out_str


class Test_Lbry(unittest.TestCase):

    def test_hash(self):

        test = get_powhash("test string")
        value="485f3920d48a0448034b0852d1489cfa475341176838c7d36896765221be35ce"
        self.assertEqual(test,value)

        test = get_powhash("a"*70)
        value="eb44af2f41e7c6522fb8be4773661be5baa430b8b2c3a670247e9ab060608b75"
        self.assertEqual(test,value)

        test = get_powhash("d"*140)
        value="74044747b7c1ff867eb09a84d026b02d8dc539fb6adcec3536f3dfa9266495d9"
        self.assertEqual(test,value)

    
    def test_verify_proof(self):
        claim1_name = 97 #'a'
        claim1_txid = 'bd9fa7ffd57d810d4ce14de76beea29d847b8ac34e8e536802534ecb1ca43b68'
        claim1_outpoint = 0
        claim1_height = 10 
        claim1_node_hash = claims.get_hash_for_outpoint(binascii.unhexlify(claim1_txid)[::-1],claim1_outpoint,claim1_height)

        claim2_name = 98 #'b' 
        claim2_txid = 'ad9fa7ffd57d810d4ce14de76beea29d847b8ac34e8e536802534ecb1ca43b68' 
        claim2_outpoint = 1
        claim2_height = 5
        claim2_node_hash = claims.get_hash_for_outpoint(binascii.unhexlify(claim2_txid)[::-1],claim2_outpoint,claim2_height)
       
        to_hash1 = claim1_node_hash
        hash1 = lbrycrd.Hash(to_hash1)
        to_hash2 = chr(claim1_name)+hash1 + chr(claim2_name)+claim2_node_hash

        root_hash = lbrycrd.Hash(to_hash2)

        proof={'last takeover height':claim1_height,'txhash':claim1_txid,'nOut':claim1_outpoint,
               'nodes':[ 
                        {'children':
                            [{'character':97},{'character':98,'nodeHash':claim2_node_hash[::-1].encode('hex')}],
                        },
                        {'children':
                            [],
                        },

                    ]
              }
       
        out = claims.verify_proof(proof,root_hash[::-1].encode('hex'),'a')
        self.assertEqual(out,True)



    def test_claimid_hash(self):
        txid= "4d08012feefec192bdb45495dcedc171a56d369539ce2d589e3e1ec81a882bb4"
        nout = 1
        claim_id = "a438fc7701e10e0e5c41d7a342be1190d9bed57b"
        
        
        out = lbrycrd.claim_id_hash(lbrycrd.rev_hex(txid).decode('hex'),nout)
        self.assertEqual(claim_id,lbrycrd.rev_hex(out.encode('hex')))
