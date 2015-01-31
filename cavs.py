
import itertools
import re
import unittest

import drbg

def readlines (input_file):
    with open(input_file) as fp:
        for lineno, line in enumerate(fp):
            yield lineno, line.strip()

def case_generator (lines, algs):
    instance = {'calls': []}
    call = {}
    base = None
    count = -1

    for lineno, line in lines:
        if len(line) > 3 and line[1:-1] in algs:
            base = {'alg': line[1:-1]}
            instance = {'calls': []}
            call = {}
            continue

        if len(line) > 3 and line[0] == '[' and line[-1] == ']':
            key, value = line[1:-1].split('=')
            base[key.strip()] = value.strip()
            continue

        matches = re.match('^COUNT = (\d+)$', line)
        if matches:
            count = int(matches.group(1))
            instance['line'] = lineno
            instance['count'] = count

            if count > 0:
                yield dict(instance, **base)

                instance = {'calls': []}
                call = {}

            continue

        matches = re.match(r'^\*\* ([^:]+):$', line)
        if matches:
            command = matches.group(1)
            call['call'] = command

            for lineno, line in lines:
                if line == '':
                    break
                elif '=' in line:
                    key, value = line.split('=')
                    call[key.strip()] = value.strip()

            instance['calls'].append(call)
            call = {}
        
        if '=' in line:
            key, value = line.split('=')        
            call[key.strip()] = value.strip()
            continue

def find_cases (input_file):
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

    data['cases'] = case_generator(lines, algs)
    return data


class CTRDRBGTestCase ():

    def fromhex (self, b):
        return bytes(bytearray.fromhex(b))

    def compare_state (self, D, call):
        Key = getattr(D, '_{}__key'.format(type(D).__name__))
        V = getattr(D, '_{}__V'.format(type(D).__name__))

        self.assertEqual(Key, self.fromhex(call['Key']))
        self.assertEqual(V, self.fromhex(call['V']))

    def test_ctr_drbg (self):
        alg = {
            'AES-128 no df': 'aes128',
            'AES-192 no df': 'aes192',
            'AES-256 no df': 'aes256',
        }[self.case['alg']]

        D = None

        for call in self.case['calls']:
            self.assertTrue(D or call['call'] == 'INSTANTIATE')
            
            if call['call'] == 'INSTANTIATE':
                entropy = self.fromhex(call['EntropyInput'])
                data = None

                if call['PersonalizationString'] != '':
                    data = self.fromhex(call['PersonalizationString'])

                D = drbg.CTRDRBG(alg, entropy, data)
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

                out = D.generate(int(case['ReturnedBitsLen']) // 8, data)
                self.compare_state(D, call)

                if call.get('ReturnedBits', '') != '':
                    rbits = self.fromhex(call['ReturnedBits'])
                    self.assertEqual(out, rbits)
       
        # self.compare_state(D, 0)

        # for n, call in enumerate(self.data['calls'][1:]):
        #     self.call(D, call)
        #     self.compare_state(D, n + 1)


if __name__ == '__main__':
    pr_false = find_cases('nist/drbgvectors_pr_false/CTR_DRBG.txt')
    no_reseed = find_cases('nist/drbgvectors_no_reseed/CTR_DRBG.txt')

    for case in itertools.chain(pr_false['cases'], no_reseed['cases']):
        if not re.match('^AES-\d+ no df$', case['alg']):
            continue

        name = 'TestCase_{}_{}'.format(case['line'],
                                       case['alg'].replace(' ', '_').\
                                       replace('-', '_'))
        
        globals()[name] = type(name, (unittest.TestCase, CTRDRBGTestCase), {'case': case})


    unittest.main()