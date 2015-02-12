
import itertools
import os, os.path
import re
import unittest

import drbg

def readlines (input_file):
    with open(input_file) as fp:
        for lineno, line in enumerate(fp):
            yield lineno, line.strip('\r\n')

def case_generator (lines, suffix=''):
    case_info = None
    case = None
    call = None
    
    for lineno, line in lines:
        if line == '':
            continue

        matches = re.match(r'^\[([^=]+)(?: =(.*))?\]$', line)
        if matches:
            key, value = matches.groups()

            if value is None:
                case_info = {'alg': '{}{}'.format(key.strip(), suffix)}
            else:
                try:
                    case_info[key.strip()] = int(value.strip())
                except:
                    case_info[key.strip()] = value.strip()

            continue

        matches = re.match('^COUNT = (\d+)$', line)
        if matches:
            if case:
                case['calls'] = case['calls'][:-1]
                yield case

            call = {}
            case = dict({
                'count': int(matches.group(1)),
                'line': lineno,
                'calls': [{}]
            }, **case_info)
            continue

        if line.startswith('**'):
           case['calls'][-1]['call'] = line[3:-1]
           case['calls'].append({})

        matches = re.match('^(\s*[^ ]+)\s+=(?: (.*))?$', line)
        if matches:
            key, value = matches.groups()
            idx = -2 if re.match('^\s+', key) else -1
            case['calls'][idx][key.strip()] = value.strip()

def find_cases (input_file, suffix):
    lines = readlines(input_file)
    data = {}
    algs = None

    # Scan for options string
    for lineno, line in lines:
        matches = re.match('# ([^ ]+) options: (.*)$', line)

        if matches:
            mode, algs = matches.groups()
            data['mode'] = mode

            algs = [_.strip() for _ in algs.split('::')]
            data['algs'] = algs
            break

    if algs is None:
        raise RuntimeError('No options string found.')

    data['cases'] = case_generator(lines, suffix)
    return data


class DRBGTestCase ():

    def fromhex (self, b):
        return bytes(bytearray.fromhex(b))

    def compare_state (self, D, call):
        try:
            if isinstance(D, (drbg.CTRDRBG, drbg.HMACDRBG)):
                return self.compare_ctr_state(D, call)
            elif isinstance(D, drbg.HashDRBG):
                return self.compare_hash_state(D, call)
        except:
            import pprint
            pprint.pprint(self.case)
            pprint.pprint(call)
            print('')
            raise

    def compare_ctr_state (self, D, call):
        Key = getattr(D, '_{}__key'.format(type(D).__name__))
        V = getattr(D, '_{}__V'.format(type(D).__name__))

        self.assertEqual(Key, self.fromhex(call['Key']))
        self.assertEqual(V, self.fromhex(call['V']))

    def compare_hash_state (self, D, call):
        C = getattr(D, '_{}__C'.format(type(D).__name__))
        V = getattr(D, '_{}__V'.format(type(D).__name__))

        self.assertEqual(C, self.fromhex(call['C']))
        self.assertEqual(V, self.fromhex(call['V']))

    def test_drbg (self):
        alg = {
            '3KeyTDEA no df': 'tdea',
            'AES-128 no df': 'aes128',
            'AES-192 no df': 'aes192',
            'AES-256 no df': 'aes256',
            'SHA-1': 'sha1',
            'SHA-224': 'sha224',
            'SHA-256': 'sha256',
            'SHA-384': 'sha384',
            'SHA-512': 'sha512',
            'SHA-1hmac': 'sha1hmac',
            'SHA-224hmac': 'sha224hmac',
            'SHA-256hmac': 'sha256hmac',
            'SHA-384hmac': 'sha384hmac',
            'SHA-512hmac': 'sha512hmac',
        }[self.case['alg']]

        D = None

        for call in self.case['calls']:
            self.assertTrue(D or call['call'] == 'INSTANTIATE')
            
            if call['call'] == 'INSTANTIATE':
                entropy = self.fromhex(call['EntropyInput'])
                data = None

                if call['PersonalizationString'] != '':
                    data = self.fromhex(call['PersonalizationString'])

                if alg.startswith('aes') or alg == 'tdea':
                    D = drbg.CTRDRBG(alg, entropy, data)
                else:
                    nonce = self.fromhex(call['Nonce'])

                    if alg.endswith('hmac'):
                        D = drbg.HMACDRBG(alg, entropy, nonce, data)
                    else:
                        D = drbg.HashDRBG(alg, entropy, nonce, data)
                self.compare_state(D, call)

            elif call['call'] == 'RESEED':
                entropy = self.fromhex(call['EntropyInputReseed'])
                data = None

                if call['AdditionalInputReseed'] != '':
                    data = self.fromhex(call['AdditionalInputReseed'])

                D.reseed(entropy, data)
                self.compare_state(D, call)

            elif call['call'].startswith('GENERATE'):
                data = None

                if call['AdditionalInput'] != '':
                    data = self.fromhex(call['AdditionalInput'])

                out = D.generate(int(self.case['ReturnedBitsLen']) // 8, data)
                self.compare_state(D, call)

                if call.get('ReturnedBits', '') != '':
                    rbits = self.fromhex(call['ReturnedBits'])
                    self.assertEqual(out, rbits)

def generate_test_cases (mechs):
    cases = {}

    for subtype in ['no_reseed', 'pr_false']:
        path = os.path.join('nist', 'drbgvectors_{}'.format(subtype))
        iters = []

        for mech, suffix in mechs:
            filename = os.path.join(path, '{}_DRBG.txt'.format(mech))
            it = find_cases(filename, suffix)['cases']
            iters.append(it)

        for case in itertools.chain(*iters):
            if not re.match('^(3KeyTDEA|(AES|SHA)-\d+)( no df|hmac)?$', case['alg']):
                continue

            alg = re.sub('[-\s]', '_', case['alg'])
            name = '{}_{}_{}'.format(alg, subtype, case['line'])
            
            cls = type(name, (unittest.TestCase, DRBGTestCase), {'case': case})
            cases[name] = cls

    return cases

if __name__ == '__main__':
    mechs = [
        ('Hash', ''),
        ('CTR', ''),
        ('HMAC', 'hmac'),
    ]
    globals().update(generate_test_cases(mechs))
    unittest.main()
