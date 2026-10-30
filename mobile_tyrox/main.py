from kivy.app import App
from kivy.lang import Builder
from kivy.clock import Clock
from kivy.properties import StringProperty, ListProperty, BooleanProperty
from kivy.uix.popup import Popup
from kivy.uix.filechooser import FileChooserListView
from kivy.uix.boxlayout import BoxLayout
from kivy.uix.button import Button
from kivy.uix.label import Label
from threading import Thread, Event
from urllib.parse import quote
import socket, json, os, hashlib, ssl, http.client, mimetypes, uuid, time

KV = r'''
#:import dp kivy.metrics.dp
BoxLayout:
    orientation: 'vertical'
    padding: dp(18)
    spacing: dp(10)
    canvas.before:
        Color:
            rgba: .047, .051, .071, 1
        Rectangle:
            pos: self.pos
            size: self.size
    BoxLayout:
        size_hint_y: None
        height: dp(58)
        orientation: 'vertical'
        Label:
            text: '[b]TYROX[/b] [color=\"#9B83FF\"]MOBILE[/color]'
            markup: True
            font_size: '25sp'
            halign: 'left'
            text_size: self.size
            valign: 'middle'
        Label:
            text: 'SECURE LOCAL NETWORK CONTROL'
            color: .60, .62, .69, 1
            font_size: '10sp'
            halign: 'left'
            text_size: self.size
    BoxLayout:
        size_hint_y: None
        height: dp(42)
        spacing: dp(8)
        TextInput:
            id: host
            hint_text: 'Computer IP address'
            multiline: False
        TextInput:
            id: port
            text: '47821'
            hint_text: 'Port'
            size_hint_x: .28
            multiline: False
            input_filter: 'int'
    TextInput:
        id: token
        hint_text: 'Pairing token'
        password: True
        multiline: False
        size_hint_y: None
        height: dp(44)
    TextInput:
        id: fingerprint
        hint_text: 'SHA-256 certificate fingerprint (64 hex characters)'
        multiline: False
        size_hint_y: None
        height: dp(44)
    BoxLayout:
        size_hint_y: None
        height: dp(46)
        spacing: dp(8)
        Button:
            text: 'Connect securely'
            background_normal: ''
            background_color: .42, .29, .95, 1
            on_release: app.connect_device()
        Button:
            text: 'Discover'
            size_hint_x: .38
            on_release: app.discover()
    Label:
        id: status
        text: 'Not connected. Enter the PC address, pairing token and fingerprint.'
        size_hint_y: None
        height: dp(48)
        color: .88, .89, .93, 1
        halign: 'left'
        valign: 'middle'
        text_size: self.size
    BoxLayout:
        size_hint_y: None
        height: dp(36)
        Label:
            text: '[b]REMOTE FILES[/b]'
            markup: True
            color: .68, .69, .75, 1
            halign: 'left'
            text_size: self.size
        Button:
            text: 'Refresh'
            size_hint_x: .32
            on_release: app.refresh_files()
    TextInput:
        id: remote_path
        hint_text: 'Remote folder path (blank = shared root)'
        multiline: False
        size_hint_y: None
        height: dp(42)
    BoxLayout:
        size_hint_y: None
        height: dp(44)
        spacing: dp(8)
        Button:
            text: 'Send file'
            on_release: app.choose_upload()
        Button:
            text: 'Download selected'
            on_release: app.download_selected()
    ScrollView:
        do_scroll_x: False
        GridLayout:
            id: file_list
            cols: 1
            size_hint_y: None
            height: self.minimum_height
            spacing: dp(5)
    Label:
        text: 'TYROX Alpha · Python mobile client'
        size_hint_y: None
        height: dp(22)
        color: .38, .40, .46, 1
        font_size: '10sp'
'''

class PinnedHTTPS:
    """HTTPS client that checks the exact certificate SHA-256 before sending HTTP data."""
    def __init__(self, host, port, token, fingerprint, timeout=15):
        self.host, self.port, self.token = host, int(port), token
        self.expected = ''.join(c for c in fingerprint.lower() if c in '0123456789abcdef')
        if len(self.expected) != 64:
            raise ValueError('Fingerprint must contain exactly 64 hexadecimal characters.')
        if len(token) < 16:
            raise ValueError('Pairing token is too short.')
        self.timeout = timeout

    def _connection(self):
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        conn = http.client.HTTPSConnection(self.host, self.port, context=context, timeout=self.timeout)
        conn.connect()
        cert = conn.sock.getpeercert(binary_form=True)
        actual = hashlib.sha256(cert).hexdigest()
        if not __import__('hmac').compare_digest(actual, self.expected):
            conn.close()
            raise ssl.SSLError('Certificate fingerprint mismatch. Connection rejected.')
        return conn

    def request(self, method, path, body=None, headers=None):
        conn = self._connection()
        h = {'Authorization': 'Bearer ' + self.token, 'Connection': 'close'}
        if headers: h.update(headers)
        try:
            conn.request(method, path, body=body, headers=h)
            response = conn.getresponse()
            data = response.read()
            if response.status < 200 or response.status >= 300:
                try: detail = json.loads(data.decode('utf-8')).get('error', data.decode('utf-8'))
                except Exception: detail = data.decode('utf-8', 'replace')
                raise RuntimeError(f'HTTP {response.status}: {detail}')
            return response.status, response.getheaders(), data
        finally:
            conn.close()

    def list_files(self, path=''):
        _, _, data = self.request('GET', '/api/files?path=' + quote(path, safe='/'))
        return json.loads(data.decode('utf-8')).get('entries', [])

    def upload(self, filepath, remote_path=''):
        name = os.path.basename(filepath)
        boundary = '----TYROX' + uuid.uuid4().hex
        mime = mimetypes.guess_type(name)[0] or 'application/octet-stream'
        prefix = (f'--{boundary}\r\nContent-Disposition: form-data; name="files"; filename="{name}"\r\n'
                  f'Content-Type: {mime}\r\n\r\n').encode()
        suffix = f'\r\n--{boundary}--\r\n'.encode()
        size = os.path.getsize(filepath)
        body_length = len(prefix) + size + len(suffix)
        conn = self._connection()
        headers = {'Authorization': 'Bearer ' + self.token, 'Content-Type': 'multipart/form-data; boundary=' + boundary,
                   'Content-Length': str(body_length), 'Connection': 'close'}
        try:
            conn.putrequest('POST', '/api/upload?path=' + quote(remote_path, safe='/'))
            for k, v in headers.items(): conn.putheader(k, v)
            conn.endheaders()
            conn.send(prefix)
            with open(filepath, 'rb') as f:
                while True:
                    chunk = f.read(1024 * 1024)
                    if not chunk: break
                    conn.send(chunk)
            conn.send(suffix)
            response = conn.getresponse(); data = response.read()
            if response.status < 200 or response.status >= 300:
                try: detail = json.loads(data.decode()).get('error', data.decode())
                except Exception: detail = data.decode('utf-8', 'replace')
                raise RuntimeError(f'Upload failed ({response.status}): {detail}')
            return json.loads(data.decode('utf-8'))
        finally: conn.close()

    def download(self, remote_path, destination):
        conn = self._connection()
        try:
            conn.request('GET', '/api/download?path=' + quote(remote_path, safe='/'), headers={'Authorization':'Bearer '+self.token})
            response = conn.getresponse()
            if response.status < 200 or response.status >= 300:
                raise RuntimeError(f'Download failed: HTTP {response.status}')
            with open(destination, 'wb') as f:
                while True:
                    chunk = response.read(1024 * 1024)
                    if not chunk: break
                    f.write(chunk)
        finally: conn.close()

class TyroxMobile(App):
    status_text = StringProperty('Not connected.')
    def build(self):
        self.root = Builder.load_string(KV)
        self.api = None
        self.entries = []
        self.selected = None
        self.discovery_stop = Event()
        return self.root

    def _ui_status(self, message):
        self.root.ids.status.text = message

    def connect_device(self):
        host = self.root.ids.host.text.strip()
        token = self.root.ids.token.text.strip()
        fp = self.root.ids.fingerprint.text.strip()
        try:
            port = int(self.root.ids.port.text.strip() or '47821')
            if not host or not (1 <= port <= 65535): raise ValueError('Enter a valid IP and port.')
            self.api = PinnedHTTPS(host, port, token, fp)
        except Exception as e:
            self._ui_status(str(e)); return
        self._ui_status('Verifying TLS certificate and pairing token…')
        def work():
            try:
                _, _, raw = self.api.request('GET', '/api/health')
                data = json.loads(raw.decode())
                Clock.schedule_once(lambda dt: self._connected(data), 0)
            except Exception as e: Clock.schedule_once(lambda dt: self._ui_status('Connection error: ' + str(e)), 0)
        Thread(target=work, daemon=True).start()

    def _connected(self, data):
        self._ui_status(f"Connected securely to {data.get('name', 'computer')} · {data.get('version', '')}")
        self.refresh_files()

    def refresh_files(self):
        if not self.api:
            self._ui_status('Connect first.'); return
        path = self.root.ids.remote_path.text.strip()
        self._ui_status('Loading remote files…')
        def work():
            try:
                entries = self.api.list_files(path)
                Clock.schedule_once(lambda dt: self._show_files(entries), 0)
            except Exception as e: Clock.schedule_once(lambda dt: self._ui_status(str(e)), 0)
        Thread(target=work, daemon=True).start()

    def _show_files(self, entries):
        self.entries = entries; self.selected = None
        box = self.root.ids.file_list; box.clear_widgets()
        for entry in entries:
            if entry.get('isSymbolicLink'): continue
            is_dir = bool(entry.get('isDirectory'))
            size = entry.get('size', 0)
            label = ('▸  ' if is_dir else '   ') + entry.get('name', '?') + ('/' if is_dir else f'   ·   {self._size(size)}')
            btn = Button(text=label, size_hint_y=None, height=46, background_normal='',
                         background_color=(.12,.13,.18,1), halign='left')
            btn.bind(on_release=lambda _b, item=entry: self._select_entry(item))
            box.add_widget(btn)
        self._ui_status(f'{len(entries)} items listed.')

    def _select_entry(self, item):
        if item.get('isDirectory'):
            current = self.root.ids.remote_path.text.strip().strip('/')
            self.root.ids.remote_path.text = '/'.join(x for x in (current, item['name']) if x)
            self.refresh_files()
        else:
            self.selected = item
            self._ui_status('Selected: ' + item.get('name', 'file'))

    @staticmethod
    def _size(n):
        n = int(n or 0)
        if n < 1024: return f'{n} B'
        if n < 1024**2: return f'{n/1024:.1f} KB'
        return f'{n/1024**2:.1f} MB'

    def choose_upload(self):
        if not self.api: self._ui_status('Connect first.'); return
        chooser = FileChooserListView(path=os.path.expanduser('~'), filters=['*'])
        layout = BoxLayout(orientation='vertical', spacing=8)
        layout.add_widget(chooser)
        actions = BoxLayout(size_hint_y=None, height=46, spacing=8)
        popup = Popup(title='Choose a file to send', content=layout, size_hint=(.94,.9))
        cancel = Button(text='Cancel'); send = Button(text='Send')
        actions.add_widget(cancel); actions.add_widget(send); layout.add_widget(actions)
        cancel.bind(on_release=popup.dismiss)
        send.bind(on_release=lambda *_: self._upload_path(chooser.selection[0] if chooser.selection else '', popup))
        popup.open()

    def _upload_path(self, path, popup):
        if not path or os.path.isdir(path): self._ui_status('Select one file.'); return
        popup.dismiss(); self._ui_status('Uploading…')
        remote = self.root.ids.remote_path.text.strip()
        def work():
            try:
                result = self.api.upload(path, remote)
                Clock.schedule_once(lambda dt: self._ui_status('Uploaded successfully: ' + os.path.basename(path)), 0)
                Clock.schedule_once(lambda dt: self.refresh_files(), 0)
            except Exception as e: Clock.schedule_once(lambda dt: self._ui_status(str(e)), 0)
        Thread(target=work, daemon=True).start()

    def download_selected(self):
        if not self.api or not self.selected: self._ui_status('Connect and select a file first.'); return
        item = self.selected
        remote = '/'.join(x for x in (self.root.ids.remote_path.text.strip().strip('/'), item['name']) if x)
        dest = os.path.join(self.user_data_dir, item['name'])
        self._ui_status('Downloading to app storage: ' + dest)
        def work():
            try:
                self.api.download(remote, dest)
                Clock.schedule_once(lambda dt: self._ui_status('Saved inside TYROX app storage: ' + dest), 0)
            except Exception as e: Clock.schedule_once(lambda dt: self._ui_status(str(e)), 0)
        Thread(target=work, daemon=True).start()

    def discover(self):
        self._ui_status('Listening for TYROX devices on UDP 47822…')
        def work():
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            try:
                sock.bind(('', 47822)); sock.settimeout(5)
                found = {}
                end = time.time() + 5
                while time.time() < end:
                    try: raw, addr = sock.recvfrom(4096)
                    except socket.timeout: break
                    try:
                        d = json.loads(raw.decode('utf-8'))
                        if d.get('protocol') == 'tyrox-discovery' and d.get('type') == 'hello':
                            found[addr[0]] = d
                    except Exception: pass
                if found:
                    first = next(iter(found.items()))
                    ip, d = first
                    def apply(_dt):
                        self.root.ids.host.text = ip
                        self.root.ids.port.text = str(d.get('port', 47821))
                        self.root.ids.fingerprint.text = d.get('fingerprint', '')
                        self._ui_status('Found ' + str(d.get('name', ip)) + '. Paste its pairing token to connect.')
                    Clock.schedule_once(apply, 0)
                else: Clock.schedule_once(lambda dt: self._ui_status('No TYROX device discovered. Enter IP manually.'), 0)
            finally: sock.close()
        Thread(target=work, daemon=True).start()

if __name__ == '__main__':
    TyroxMobile().run()
