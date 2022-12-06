class Print:
    colors = {
      "green": "\033[92m",
      "blue": "\033[94m",
      "yellow": "\033[93m",
      "red": "\033[91m",
      "endc": "\033[0m"
    }

    def __init__(self, quiet=False):
        self.quiet = quiet
  
  # green [+]
    def success(self, text):
        if not self.quiet:
            print(self.colors["green"] + f'[+] {text}' + self.colors["endc"])
  # blue [*]
    def info(self, text):
        if not self.quiet:
            print(self.colors["blue"] + f'[*] {text}' + self.colors["endc"])
  # yellow [!]
    def warning(self, text):
        if not self.quiet:
            print(self.colors["yellow"] + f'[!] {text}' + self.colors["endc"])
  # red [-]
    def error(self, text):
        if not self.quiet:
            print(self.colors["red"] + f'[-] {text}' + self.colors["endc"])

    def green(self, text):
        if not self.quiet:
            print(self.colors["green"] + f"{text}" + self.colors["endc"])

    def flag(self, text):
        with open("flags.pot", "a") as fd:
            fd.write(f"{text}\n")

