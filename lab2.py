#!/usr/bin/env python
# coding: utf-8

# In[1]:


import pyftpdlib
import hashlib
import logging
import os
from hashlib import md5

from pyftpdlib.authorizers import DummyAuthorizer, AuthenticationFailed
from pyftpdlib.handlers import FTPHandler, ThrottledDTPHandler
from pyftpdlib.servers import ThreadedFTPServer


# In[2]:


def hash(string):
    return md5(string.strip().encode()).hexdigest()


# In[3]:


commands = {"DELE": "deleting a file",
            "RMD": "deleting a folder",
            "CWD": "changing a directory",
            "MKD": "creating a folder",
            "PWD": "checking a current directiry",
            "PORT": "transition to an active mode",
            "PASV": "transition to a passive mode",
            "LIST": "listing of a dirrectory",
            "RETR": "downloading a file",
            "STOR": "uploading a file",
            "ABOR": "aborting a transition",
            "RNTO": "renaming of a file"}


# In[4]:


class MyHandler(FTPHandler):

    def on_connect(self):
        print("connected, host = ", self.remote_ip, ", port = ", self.remote_port)

    def on_disconnect(self):
        print("disconnected, host = ", self.remote_ip, ", port = ", self.remote_port)

    def on_login(self, username):
        print(username, ' was succsessfuly logged in')

    def on_logout(self, username):
        print(username, ' was succsessfuly logged out')

    def on_file_sent(self, file):
        print('file succsessfuly sent')

    def on_file_received(self, file):
        print('file sucsessfuly received')
        pass

    def on_incomplete_file_sent(self, file):
        print('file unsuccsessfuly sent')

    def on_incomplete_file_received(self, file):
        print('file unsuccsessfuly received')
        os.remove(file)

    def pre_process_command(self, line, cmd, arg):
        kwargs = {}
        if cmd == "SITE" and arg:
            cmd = "SITE %s" % arg.split(' ')[0].upper()
            arg = line[len(cmd) + 1:]
        if cmd != 'PASS':
            self.logline("<- %s" % line)
        else:
            self.logline("<- %s %s" % (line.split(' ')[0], '*' * 6))
        if not cmd in self.proto_cmds:
            if cmd[-4:] in ('ABOR', 'STAT', 'QUIT'):
                cmd = cmd[-4:]
            else:
                msg = 'Command "%s" not understood.' % cmd
                self.respond('500 ' + msg)
                if cmd:
                    self.log_cmd(cmd, arg, 500, msg)
                return
        if not arg and self.proto_cmds[cmd]['arg'] == True:
            msg = "Syntax error: command needs an argument."
            self.respond("501 " + msg)
            self.log_cmd(cmd, "", 501, msg)
            return
        if arg and self.proto_cmds[cmd]['arg'] == False:
            msg = "Syntax error: command does not accept arguments."
            self.respond("501 " + msg)
            self.log_cmd(cmd, arg, 501, msg)
            return
        if not self.authenticated:
            if self.proto_cmds[cmd]['auth'] or (cmd == 'STAT' and arg):
                msg = "Log in with USER and PASS first."
                self.respond("530 " + msg)
                self.log_cmd(cmd, arg, 530, msg)
            else:
                self.process_command(cmd, arg)
                return
        else:
            if (cmd == 'STAT') and not arg:
                self.ftp_STAT(u(''))
                return
            if self.proto_cmds[cmd]['perm'] and (cmd != 'STOU'):
                if cmd in ('CWD', 'XCWD'):
                    arg = self.fs.ftp2fs(arg or u('/'))
                elif cmd in ('CDUP', 'XCUP'):
                    arg = self.fs.ftp2fs(u('..'))
                elif cmd == 'LIST':
                    if arg.lower() in ('-a', '-l', '-al', '-la'):
                        arg = self.fs.ftp2fs(self.fs.cwd)
                    else:
                        arg = self.fs.ftp2fs(arg or self.fs.cwd)
                elif cmd == 'STAT':
                    if glob.has_magic(arg):
                        msg = 'Globbing not supported.'
                        self.respond('550 ' + msg)
                        self.log_cmd(cmd, arg, 550, msg)
                        return
                    arg = self.fs.ftp2fs(arg or self.fs.cwd)
                elif cmd == 'SITE CHMOD':
                    if not ' ' in arg:
                        msg = "Syntax error: command needs two arguments."
                        self.respond("501 " + msg)
                        self.log_cmd(cmd, "", 501, msg)
                        return
                    else:
                        mode, arg = arg.split(' ', 1)
                        arg = self.fs.ftp2fs(arg)
                        kwargs = dict(mode=mode)
                else:
                    arg = self.fs.ftp2fs(arg or self.fs.cwd)
                if not self.fs.validpath(arg):
                    line = self.fs.fs2ftp(arg)
                    msg = '"%s" points to a path which is outside '                           "the user's root directory" % line
                    self.respond("550 %s." % msg)
                    self.log_cmd(cmd, arg, 550, msg)
                    return
            perm = self.proto_cmds[cmd]['perm']
            if perm is not None and cmd != 'STOU':
                if not self.authorizer.has_perm(self.username, perm, arg):
                    if cmd in commands:
                        print(self.username, " has not enough priveleges to commit", commands[cmd])
                    else:
                        print(self.username, " has not enough priveleges to commit", cmd)
                    msg = "Not enough privileges."
                    self.respond("550 " + msg)
                    self.log_cmd(cmd, arg, 550, msg)
                    return
                else:
                    if cmd in commands:
                        print(self.username, "has enough priveleges to commit", commands[cmd])
                    else:
                        print(self.username, "has enough priveleges to commit", cmd)
            self.process_command(cmd, arg, **kwargs)

        def handle_error(self):
            try:
                self.log_exception(self)
            except Exception:
                logger.critical(traceback.format_exc())


# In[5]:


class MyAuthorizer(DummyAuthorizer):
    def validate_authentication(self, username, password, handler):
        if username == 'anonymous':
            return
        password = hash(password)
        if not username in self.user_table:
            print('Authentication failed, no such user')
            raise AuthenticationFailed("Authentication failed, no such user")
        if self.user_table[username]['pwd'] != password:
            print('Authentication failed, wrong password')
            raise AuthenticationFailed("Authentication failed, wrong password")


# In[6]:


def main():
    authorizer = MyAuthorizer()

    authorizer.add_user('admin', hash('12345'), os.getcwd(), perm='elradfmwMT')
    authorizer.add_user('reader', hash('54321'), os.getcwd(), perm='elr')
    authorizer.add_user('writer', hash('67890'), os.getcwd(), perm='elrafmw')
    authorizer.add_anonymous(os.getcwd(), perm='el')

    handler = MyHandler
    handler.authorizer = authorizer
    handler.banner = "pyftpdlib based ftpd ready."
    handler.passive_ports = range(60000, 65535)
    handler.permit_privileged_ports = True
    # handler.masquerade_address = '81.177.126.91'
    handler.active_dtp = pyftpdlib.handlers.ActiveDTP
    handler.passive_dtp = pyftpdlib.handlers.PassiveDTP

    dtp_handler = ThrottledDTPHandler
    dtp_handler.read_limit = 30720
    dtp_handler.write_limit = 30720
    handler.dtp_handler = dtp_handler

    localhost = '172.16.63.88'
    port = 60
    address = (localhost, port)
    server = ThreadedFTPServer(address, handler)
    server.max_cons = 256
    print("server is active, host = ", localhost, "port = ", port)
    server.serve_forever()





if __name__ == '__main__':
    main()