class Fart_Print:
  def __init__(self, text):
    self.colors = {
      "green": "\033[92m",
      "blue": "\033[94m",
      "yellow": "\033[93m",
      "red": "\033[91m",
      "endc": "\033[0m"
    }
    self.text = text
  # green [+]
  def success(self):
    print(self.colors["green"] + f'[+] {self.text}' + self.colors["endc"])
  # blue [*]
  def okay(self):
    print(self.colors["blue"] + f'[*] {self.text}' + self.colors["endc"])
  # yellow [!]
  def warning(self):
    print(self.colors["yellow"] + f'[!] {self.text}' + self.colors["endc"])
  # red [-]
  def error(self):
    print(self.colors["red"] + f'[-] {self.text}' + self.colors["endc"])
