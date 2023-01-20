# Work in progress. Option by PRogers[at]Enhance.Group to say token is the filename of a token list
# Notes:
# Q: Does Validator ever get used? If so, add  the token_list option.
# SoFar:
# 2022-12-01    PRogers[at]Enhance.Group
# Accept multiple tokens from a plain text file.
# 2022-12-02    PRogers[at]Enhance.Group
# If token auth fails then wipe the already received temporary file!
# File uploads not allowed (deleted) if token list is: missing, empty, has blank lines
# File uploads not allowed (deleted) if token given is a sub-set or super-set of a valid token
# 2022-12-23    PRogers[at]Enhance.Group
# Initial rough quota enforcement to prevent DoS
# Take quota (in MB) from command line args with sane default.
# 2023-01-18    PRogers[at]Enhance.Group
# Fixed regression deleting unwanted files.
# 2023-01-19    PRogers[at]Enhance.Group
# Save space by skipping uploaded file if a file already exists with *IDENTICAL* name,size & hash.
# Test with both files under & over 1000 bytes. Single & multiple files.
# Move debug file from hard-coded to folder above argument directory.
# 2023-01-20    PRogers[at]Enhance.Group
# Add transfer log.  Add timestamp to logs.
# ToDo:
# Show the sender some incication of succesfull upload.
# Find how to prevent transfer BEFORE it uses our bandwidth
# Sanity check the token-based directory name & full path for characters or length which would be invalid for the file system
# Make tokenlist reader ignore anything after the first word, to allow comment of internal client name
# Allow directory name to be specified in the list, optionally.
# Further development:
# File size limit? - in a seperate option.

def dbm(msg): # dbm(f'SoFar __LINE__31 var="{val}" ')
    debug_file = pathlib.Path(args.directory) / '../debug.txt'
    if os.path.isfile(debug_file):
        import datetime
        ts = datetime.datetime.now().replace(microsecond=0).isoformat(' ')
        with open(debug_file, 'a') as f: f.write(ts+'\t'+msg+'\n')

def log(dst): # log(full_destination_path)
    transfer_log = pathlib.Path(args.directory) / '../transfer.log'
    if os.path.isfile(transfer_log):
        import datetime
        ts = datetime.datetime.now().replace(microsecond=0).isoformat(' ')
        with open(transfer_log, 'a') as f: f.write(ts+'\t'+str(dst)+'\n')

def get_directory_size(directory):
    import os
    """Returns the `directory` size in bytes."""
    total = 0
    try:
        # print("[+] Getting the size of", directory)
        for entry in os.scandir(directory):
            if entry.is_file():
                # if it's a file, use stat() function
                total += entry.stat().st_size
            elif entry.is_dir():
                # if it's a directory, recursively call this function
                try:
                    total += get_directory_size(entry.path)
                except FileNotFoundError:
                    pass
    except NotADirectoryError:
        # if `directory` isn't a directory, get the file size then
        return os.path.getsize(directory)
    except PermissionError:
        # if for whatever reason we can't open the folder, return 0
        return 0
    return total

def hash_file(filename):
    import hashlib
    h = hashlib.sha1()
    with open(filename,'rb') as file:
       chunk = 0
       while chunk != b'':
           chunk = file.read(1024)
           h.update(chunk)
    return h.hexdigest()

import http.server, http, cgi, pathlib, sys, argparse, ssl, os, builtins
import tempfile

# Does not seem to do be used, but leaving this import out causes uploadserver to not receive IPv4 requests when
# started with default options under Windows
import socket 

if sys.version_info.major > 3 or sys.version_info.minor >= 7:
    import functools

if sys.version_info.major > 3 or sys.version_info.minor >= 8:
    import contextlib

CSS = {
    'light': '',
    'auto': '''<style type="text/css">
@media (prefers-color-scheme: dark) {
  body {
    background-color: #000;
    color: #fff;
  }
}
</style>''',
    'dark': '''<style type="text/css">
body {
  background-color: #000;
  color: #fff;
}
</style>'''
}

def get_upload_page(theme):
    return bytes('''<!DOCTYPE html>
<html>
<head>
<title>File Upload</title>
<meta name="viewport" content="width=device-width, user-scalable=no" />''' \
    + CSS.get(theme) + '''
</head>
<body>
<h1>File Upload</h1>
<form action="upload" method="POST" enctype="multipart/form-data">
<input name="files" type="file" multiple />
<br />
<br />
Token (only needed if server was started with token option): <input name="token" type="text" />
<br />
<br />
<input type="submit" />
</form>
<p id="task"></p>
<p id="status"></p>
</body>
<script>
document.getElementsByName('token')[0].value=localStorage.token || ''

document.getElementsByTagName('form')[0].addEventListener('submit', async e => {
  e.preventDefault()
  
  localStorage.token = e.target.token.value
  
  const tokenValidationFormData = new FormData()
  tokenValidationFormData.append('token', e.target.token.value)
  
  let tokenValidationResponse;
  try {
    tokenValidationResponse = await fetch('/upload/validateToken', { method: 'POST', body: tokenValidationFormData})
  } catch (e) {
    tokenValidationResponse = {
      ok: false,
      status: "Token validation unsuccessful",
      statusText: e.message,
    }
  }
  
  if (!tokenValidationResponse.ok) {
    let message = `${tokenValidationResponse.status}: ${tokenValidationResponse.statusText}`
    document.getElementById('status').textContent = message
    return
  }
  message = `Success: ${tokenValidationResponse.statusText}`
  const uploadFormData = new FormData(e.target)
  const filenames = uploadFormData.getAll('files').map(v => v.name).join(', ')
  const uploadRequest = new XMLHttpRequest()
  uploadRequest.open(e.target.method, e.target.action)
  uploadRequest.timeout = 3600000
  
  uploadRequest.onreadystatechange = () => {
    if (uploadRequest.readyState === XMLHttpRequest.DONE) {
      let message = `${uploadRequest.status}: ${uploadRequest.statusText}`
      if (uploadRequest.status === 204) message = `Success: ${uploadRequest.statusText}`
      if (uploadRequest.status === 0) message = 'Connection failed'
      document.getElementById('status').textContent = message
    }
  }
  
  uploadRequest.upload.onprogress = e => {
    let message = e.loaded === e.total ? 'Saving???' : `${Math.floor(100*e.loaded/e.total)}% [${e.loaded >> 10} / ${e.total >> 10}KiB]`
    document.getElementById("status").textContent = message
  }
  
  uploadRequest.send(uploadFormData)
  
  document.getElementById('task').textContent = `Uploading ${filenames}:`
  document.getElementById('status').textContent = '0%'
})
</script>
</html>''', 'utf-8')

def send_upload_page(handler):
    handler.send_response(http.HTTPStatus.OK)
    handler.send_header('Content-Type', 'text/html; charset=utf-8')
    handler.send_header('Content-Length', len(get_upload_page(args.theme)))
    handler.end_headers()
    handler.wfile.write(get_upload_page(args.theme))

class PersistentFieldStorage(cgi.FieldStorage):
    # Override cgi.FieldStorage.make_file() method. Valid for Python 3.1 ~ 3.10. Modified version of the original
    # .make_file() method (base copied from Python 3.10)
    def make_file(self):
        if self._binary_file:
            return tempfile.NamedTemporaryFile(mode = 'wb+', dir = args.directory, delete = False)
        else:
            return tempfile.NamedTemporaryFile("w+", dir = args.directory, delete = False,
                encoding = self.encoding, newline = '\n')

def auto_rename(path):
    if not os.path.exists(path):
        return path
    (base, ext) = os.path.splitext(path)
    for i in range(1, sys.maxsize):
        renamed_path = f'{base} ({i}){ext}'
        if not os.path.exists(renamed_path):
            return renamed_path
    raise FileExistsError(f'File {path} already exists.')

def validate_token(handler):
    dbm(f'SoFar __LINE__216 ')
    form = PersistentFieldStorage(fp=handler.rfile, headers=handler.headers, environ={'REQUEST_METHOD': 'POST'})
    if args.token:
        # server started with token.
        if 'token' not in form or form['token'].value != args.token:
            # no token or token error
            handler.log_message('Token rejected (bad token)')
            return (http.HTTPStatus.FORBIDDEN, 'Token is enabled on this server, and your token is missing or wrong')
        return (http.HTTPStatus.NO_CONTENT, 'Token validation successful (good token)')
    return (http.HTTPStatus.NO_CONTENT, 'Token validation successful (no token required)')

def receive_upload(handler):
    dbm(f'SoFar __LINE__228  ')
    result = (http.HTTPStatus.INTERNAL_SERVER_ERROR, 'Server error')
    name_conflict = False
    
    form = PersistentFieldStorage(fp=handler.rfile, headers=handler.headers, environ={'REQUEST_METHOD': 'POST'})
    if 'files' not in form:
        return (http.HTTPStatus.BAD_REQUEST, 'Field "files" not found')
    
    fields = form['files']
    if not isinstance(fields, list):
        fields = [fields]
    
    if not all(field.file and field.filename for field in fields):
        return (http.HTTPStatus.BAD_REQUEST, 'No files selected')
    
    dbm(f'SoFar __LINE__243  ')
    token_list = [] # read secure list of multiple tokens
    if args.token and 'tokenlist' in args and args.tokenlist:
        try:
            with open(args.token, 'r') as f:
                for line in f.readlines():
                    if len(line.strip()) > 0: # ignore blank lines in token list
                        token_list.append(line.strip())
        except: pass # expected but missing token list will not allow upload.
        dbm(f'SoFar __LINE__252 tokens: {len(token_list)} ')
    
    for field in fields:
        dbm(f'SoFar __LINE__255  ')
        if field.file and field.filename:
            filename = pathlib.Path(field.filename).name
        else:
            filename = None
        
        dbm(f'SoFar __LINE__261  ')
        if args.token:
            dbm('SoFar __LINE__263 recd token: '+form['token'].value)
            # server started with token.
            if 'token' not in form or form['token'].value not in token_list:
                dbm('SoFar __LINE__266 recd token: '+form['token'].value)
                # no token or token error
                handler.log_message('Upload of "{}" rejected (bad token)'.format(filename))
                dbm('SoFar __LINE__269  ')
                field.file.close()
                dbm('SoFar __LINE__271  ')
                if hasattr(field.file, 'name'):
                    dbm(f'SoFar __LINE__273  tmp name: "{field.file.name}" ')
                    if os.path.isfile(field.file.name):
                        dbm(f'SoFar __LINE__275  tmp name: "{field.file.name}" ')
                        os.remove(field.file.name) # delete unwelcome file from invalid sender
                        # field.file.close() ; field.file.delete() # no, bad. maybe worth investigation
                dbm('SoFar __LINE__278  ')
                result = (http.HTTPStatus.FORBIDDEN, 'Tokens are enabled on this server, and your token is missing or wrong')
                dbm('SoFar __LINE__280  ')
                continue # continue so if a multiple file upload is rejected, each file will be logged
        
        if filename:
            dbm(f'SoFar __LINE__284 filename="{filename}" ')
            if token_list: # uploads from each listed token user go into their own folders
                destination_folder = pathlib.Path(args.directory) / form['token'].value
                if not os.path.exists(destination_folder):
                    os.mkdir(destination_folder)
            else:
                destination_folder = pathlib.Path(args.directory)
            destination = destination_folder / filename
            dbm(f'SoFar __LINE__292 destination="{destination}" ')
            log(destination)
            if hasattr(field.file, 'name'):
                source = field.file.name
                field.file.close()
                dbm(f'SoFar __LINE__297 source:"{source}" ')
            else:  # class '_io.BytesIO', small file (< 1000B, in cgi.py), in-memory buffer.
                tfh,source = tempfile.mkstemp(suffix='.tmp', prefix='uploadserver~', dir='.', text=False)
                bytes_written = os.write(tfh, field.file.read())
                os.close(tfh)
                dbm(f'SoFar __LINE__302 source:"{source}" ')
            # check for identical source & destination to skip & save space.
            if os.path.exists(destination):
                dbm(f'SoFar __LINE__305 source file size = {os.path.getsize(source)}')
                if os.path.getsize(source) == os.path.getsize(destination):
                    dbm(f'SoFar __LINE__307  ')
                    source_hash = hash_file(source)
                    dbm(f'SoFar __LINE__309 source hash: {source_hash} ')
                    destination_hash = hash_file(destination)
                    dbm(f'SoFar __LINE__311 destination hash: {destination_hash} ')
                    if source_hash == destination_hash:
                        dbm(f'SoFar __LINE__313 hash match')
                        os.remove(source)
                        result = (http.HTTPStatus.BAD_REQUEST, 'Identical file already exists')
                        continue
                dbm(f'SoFar __LINE__317  ')
                if args.allow_replace and os.path.isfile(destination):
                    os.remove(destination)
                    dbm(f'SoFar __LINE__320  ')
                else:
                    destination = auto_rename(destination)
                    name_conflict = True
                    dbm(f'SoFar __LINE__324  ')
            dbm(f'SoFar __LINE__325  ')
            os.rename(source, destination)
            if args.quota: # Option by PRogers[at]Enhance.Group to prevent DoS
                quota = args.quota * (1024 * 1024) # MB specified on command line
                dbm(f'SoFar __LINE__329 quota="{quota}" ')
                # so_uploaded = os.path.getsize(destination) # size of the received file. unknown until received.
                # dbm(f'SoFar __LINE__331 so_ul="{so_uploaded}" ')
                import shutil
                so_fsfree = shutil.disk_usage('.')[2]
                dbm(f'SoFar __LINE__334 so_fsf="{so_fsfree}" ')
                if so_fsfree < 4096: quota = 0 # assuming 4k sector size is lowest unit of allocation
                dbm(f'SoFar __LINE__336 quota="{quota}" ')
                # file system is out of space! Force delete of this upload.
                so_destination_folder = get_directory_size(destination_folder)
                dbm(f'SoFar __LINE__339 so_df="{so_destination_folder}" ')
                if so_destination_folder >= quota:
                    dbm(f'SoFar __LINE__341 folder exceeds quota')
                    handler.log_message('Upload of "{}" rejected (quota reached)'.format(filename))
                    if os.path.isfile(destination): os.remove(destination) # delete unwelcome file of exessive size
                    result = (http.HTTPStatus.FORBIDDEN, 'Quota has been reached - upload deleted')
                    continue # there may be other smaller files.
            
            handler.log_message(f'[Uploaded] "{filename}" --> {destination}')
            result = (http.HTTPStatus.NO_CONTENT, 'Some filename(s) changed due to name conflict' if name_conflict else 'Files accepted')
    
    return result

class SimpleHTTPRequestHandler(http.server.SimpleHTTPRequestHandler):
    def do_GET(self):
        if self.path == '/upload': send_upload_page(self)
        else: http.server.SimpleHTTPRequestHandler.do_GET(self)
    
    def do_POST(self):
        if self.path in ['/upload', '/upload/validateToken']:
            if self.path == '/upload/validateToken':
                result = validate_token(self)
            elif self.path == '/upload':
                result = receive_upload(self)
            if result[0] < http.HTTPStatus.BAD_REQUEST:
                self.send_response(result[0], result[1])
                self.end_headers()
            else:
                self.send_error(result[0], result[1])
        else:
            self.send_error(http.HTTPStatus.NOT_FOUND, 'Can only POST to /upload')

class CGIHTTPRequestHandler(http.server.CGIHTTPRequestHandler):
    def do_GET(self):
        if self.path == '/upload': send_upload_page(self)
        else: http.server.CGIHTTPRequestHandler.do_GET(self)
    
    def do_POST(self):
        if self.path in ['/upload', '/upload/validateToken']:
            if self.path == '/upload/validateToken':
                result = validate_token(self)
            elif self.path == '/upload':
                result = receive_upload(self)
            if result[0] < http.HTTPStatus.BAD_REQUEST:
                self.send_response(result[0], result[1])
                self.end_headers()
            else:
                self.send_error(result[0], result[1])
        else:
            http.server.CGIHTTPRequestHandler.do_POST(self)

def intercept_first_print():
    if args.server_certificate:
        # Use the right protocol in the first print call in case of HTTPS
        old_print = builtins.print
        def new_print(*args, **kwargs):
            old_print(args[0].replace('HTTP', 'HTTPS').replace('http', 'https'), **kwargs)
            builtins.print = old_print
        builtins.print = new_print

def ssl_wrap(socket):
    context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    server_root = pathlib.Path(args.directory).resolve()
    
    # Server certificate handling
    server_certificate = pathlib.Path(args.server_certificate).resolve()
    
    if not server_certificate.is_file():
        print('Server certificate "{}" not found, exiting'.format(server_certificate))
        sys.exit(4)
    
    if server_root in server_certificate.parents:
        print('Server certificate "{}" is inside web server root "{}", exiting'.format(server_certificate, server_root))
        sys.exit(3)
    
    context.load_cert_chain(certfile=server_certificate)
    
    if args.client_certificate:
        # Client certificate handling
        client_certificate = pathlib.Path(args.client_certificate).resolve()
        
        if not client_certificate.is_file():
            print('Client certificate "{}" not found, exiting'.format(client_certificate))
            sys.exit(4)
        
        if server_root in client_certificate.parents:
            print('Client certificate "{}" is inside web server root "{}", exiting'.format(client_certificate, server_root))
            sys.exit(3)
    
        context.load_verify_locations(cafile=client_certificate)
        context.verify_mode = ssl.CERT_REQUIRED
    
    try:
        return context.wrap_socket(socket, server_side=True)
    except ssl.SSLError as e:
        print('SSL error: "{}", exiting'.format(e))
        sys.exit(5)

def serve_forever():
    # Verify arguments in case the method was called directly
    assert hasattr(args, 'quota') and type(args.quota) is int
    assert hasattr(args, 'port') and type(args.port) is int
    assert hasattr(args, 'cgi') and type(args.cgi) is bool
    assert hasattr(args, 'allow_replace') and type(args.allow_replace) is bool
    assert hasattr(args, 'bind')
    assert hasattr(args, 'token')
    assert hasattr(args, 'theme')
    assert hasattr(args, 'server_certificate')
    assert hasattr(args, 'client_certificate')
    assert hasattr(args, 'directory') and type(args.directory) is str
    
    if args.cgi:
        handler_class = CGIHTTPRequestHandler
    elif sys.version_info.major == 3 and sys.version_info.minor < 7:
        handler_class = SimpleHTTPRequestHandler
    else:
        handler_class = functools.partial(SimpleHTTPRequestHandler, directory=args.directory)
    
    print('File upload available at /upload')
    
    if sys.version_info.major == 3 and sys.version_info.minor < 8:
        # The only difference in http.server.test() between Python 3.6 and 3.7 is the default value of ServerClass
        if sys.version_info.minor < 7:
            from http.server import HTTPServer as DefaultHTTPServer
        else:
            from http.server import ThreadingHTTPServer as DefaultHTTPServer
        
        class CustomHTTPServer(DefaultHTTPServer):
            def server_bind(self):
                bind = super().server_bind()
                if args.server_certificate:
                    self.socket = ssl_wrap(self.socket)
                return bind
        server_class = CustomHTTPServer
    else:
        class DualStackServer(http.server.ThreadingHTTPServer):
            def server_bind(self):
                # suppress exception when protocol is IPv4
                with contextlib.suppress(Exception):
                    self.socket.setsockopt(
                        socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
                bind = super().server_bind()
                if args.server_certificate:
                    self.socket = ssl_wrap(self.socket)
                return bind
        server_class = DualStackServer
    
    intercept_first_print()
    http.server.test(
        HandlerClass=handler_class,
        ServerClass=server_class,
        port=args.port,
        bind=args.bind,
    )

def main():
    global args
    
    # In Python 3.8, http.server.test() was altered to use None instead of '' as the default for its bind parameter
    if sys.version_info.major == 3 and sys.version_info.minor < 8:
        bind_default = ''
    else:
        bind_default = None
    
    parser = argparse.ArgumentParser()
    parser.add_argument('port', type=int, default=8000, nargs='?',
        help='Specify alternate port [default: 8000]')
    parser.add_argument('--cgi', action='store_true',
        help='Run as CGI Server')
    parser.add_argument('--allow-replace', action='store_true', default=False,
        help='Replace existing file if uploaded file has the same name. Auto rename by default.')
    parser.add_argument('--bind', '-b', default=bind_default, metavar='ADDRESS',
        help='Specify alternate bind address [default: all interfaces]')
    parser.add_argument('--token', '-t', type=str,
        help='Specify alternate token [default: \'\']')
    parser.add_argument('--theme', type=str, default='auto',
        choices=['light', 'auto', 'dark'], help='Specify a light or dark theme for the upload page [default: auto]')
    parser.add_argument('--server-certificate', '--certificate', '-c',
        help='Specify HTTPS server certificate to use [default: none]')
    parser.add_argument('--client-certificate',
        help='Specify HTTPS client certificate to accept for mutual TLS [default: none]')
    
    # Directory option was added to http.server in Python 3.7
    if sys.version_info.major > 3 or sys.version_info.minor >= 7:
        parser.add_argument('--directory', '-d', default=os.getcwd(),
            help='Specify alternative directory [default:current directory]')
    
    # Option by PRogers[at]Enhance.Group to say token is the filename of a token list
    parser.add_argument('--tokenlist', action='store_true', default=False,
        help='Token is the filename of a list')

    # Option by PRogers[at]Enhance.Group to prevent DoS
    parser.add_argument('--quota', type=int, default=100,
        help='Specify storage quota limit [default: 100 MB]')
    
    args = parser.parse_args()
    if not hasattr(args, 'directory'): args.directory = os.getcwd()
    
    serve_forever()
