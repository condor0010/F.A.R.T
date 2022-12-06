class Print:
    colors = {
      "green": "\033[92m",
      "blue": "\033[94m",
      "yellow": "\033[93m",
      "red": "\033[91m",
      "endc": "\033[0m"
    }
  
  # green [+]
    def success(self, text):
        print(self.colors["green"] + f'[+] {text}' + self.colors["endc"])
  # blue [*]
    def okay(self, text):
        print(self.colors["blue"] + f'[*] {text}' + self.colors["endc"])
  # yellow [!]
    def warning(self, text):
        print(self.colors["yellow"] + f'[!] {text}' + self.colors["endc"])
  # red [-]
    def error(self, text):
        print(self.colors["red"] + f'[-] {text}' + self.colors["endc"])

    def green(self, text):
        print(self.colors["green"] + f"{text}" + self.colors["endc"])
