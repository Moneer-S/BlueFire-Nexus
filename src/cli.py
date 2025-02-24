from prompt_toolkit import prompt
from prompt_toolkit.completion import WordCompleter

commands = ['scan', 'ai-predict', 'exploit']
completer = WordCompleter(commands)
user_input = prompt('> ', completer=completer)