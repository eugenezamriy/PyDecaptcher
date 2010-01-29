# -*- mode:python; coding:utf-8; -*-
# author:      Eugene G. Zamriy <bdsm@bdsm.lu>
# created:     28.01.10 15:25
# description: Python API for decaptcher.com service
# license:     New BSD license


import hashlib
import socket
import struct


__all__ = ["NetworkError", "DecaptcherError", "Captcha", "Decaptcher", "timeout_DEFAULT",
           "timeout_LONG", "timeout_30S", "timeout_60S", "timeout_90S"]


# decaptcher.com protocol commands and statuses
(__, cmd_LOGIN, cmd_BYE, cmd_RAND, cmd_HASH, __, __, cmd_OK, cmd_FAILED, cmd_OVERLOAD, cmd_BALANCE,
 cmd_TIMEOUT, cmd_PICTURE2, cmd_PICTURE_FAIL, cmd_PICTURE_TEXT) = range(15)

# picture processing timeouts
(timeout_DEFAULT, timeout_LONG, timeout_30S, timeout_60S, timeout_90S) = range(5)


class NetworkError(Exception):

    def __init__(self, message):
        """
        @type message:  str
        @param message: Error message text.
        """
        self.message = message

    def __str__(self):
        return "NetworkError: %s" % self.message


class DecaptcherError(Exception):

    def __init__(self, code):
        """
        @type code:  int
        @param code: Decaptcher.com error code (see official bindings for details).
        """
        self.code = code

    def __message(self):
        messages = { cmd_BALANCE : "balance depleted",
                     cmd_OVERLOAD : "server overloaded",
                     cmd_TIMEOUT : "image processing timeout",
                     cmd_FAILED : "server error" }
        return messages[self.code] if self.code in messages else "unknown error"

    def __str__(self):
        return "DecaptcherError: %s (%s)" % (self.message, self.code)

    message = property(__message)


class Captcha:

    def __init__(self, text, major, minor):
        self.text = text
        self.major = major
        self.minor = minor


class Decaptcher:

    __rand_SIZE = 256

    __api_VERSION = 1

    __text_OFFSET = 20

    def __init__(self, login, password, address, port, timeout=None):
        """
        @type login: str
        @param login: Service login.
        @type password: str
        @param password: Service password.
        @type address: str
        @param address: Service IP address.
        @type port: int
        @param port: Service port.
        @type timeout: Socket timeout in seconds.
        """
        self.__login = str(login)
        self.__password = password
        self.__address = address
        try:
            self.__port = int(port)
        except:
            raise ValueError("invalid port value")
        self.__timeout = timeout
        self.__socket = None

    def login(self):
        """
        Decaptcher.com login function. Must be executed before captcha solving.

        @raise NetworkError: See message attribute for details.
        """
        try:
            self.__socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.__socket.settimeout(self.__timeout)
            self.__socket.connect((self.__address, self.__port))
            self.__send_packet(cmd_LOGIN, len(self.__login), self.__login)
            version, command, size = self.__unpack_header()
            if command != cmd_RAND:
                self.__throw_network_error("wrong reply for cmd_LOGIN command")
            elif size != self.__rand_SIZE:
                self.__throw_network_error("wrong random data size")
            random_data = self.__socket.recv(int(size))
            sha = hashlib.sha256(random_data + hashlib.md5(self.__password).hexdigest() + self.__login)
            self.__send_packet(cmd_HASH, sha.digestsize, sha.digest())
            version, command, size = self.__unpack_header()
            if command != cmd_OK:
                self.__throw_network_error("can't login (%s)" % command)
        except socket.timeout, e:
            self.__throw_network_error("socket timeout")
        except Exception, e:
            self.__throw_network_error("unknown exception (%s)" % e)

    def balance(self):
        """
        Returns decaptcher.com account balance.

        @rtype:   float
        @return:  account balance.

        @raise NetworkError: See message attribute for details.
        """
        try:
            self.__send_packet(cmd_BALANCE, 0)
            version, command, size = self.__unpack_header()
            if command == cmd_BALANCE:
                return float(self.__socket.recv(size))
            self.__throw_network_error("wrong decaptcher reply")
        except socket.timeout, e:
            self.__throw_network_error("socket timeout")
        except Exception, e:
            self.__throw_network_error("unknown exception (%s)" % e)

    def process_captcha(self, image, timeout=timeout_DEFAULT):
        """
        Submits image to decaptcher.com and returns processed captcha.

        @type image:    str
        @param image:   Captcha image to process.
        @type timeout:  int
        @param timeout: Decaptcher.com image processing timeout (see timeout_* constants).
        @rtype:         Captcha
        @return:        Processed captcha.

        @raise ValueError: Wrong parameters.
        @raise DecaptcherError: Raises this exception if error code was received from decaptcher.com
        @raise NetworkError: See message attribute for details.
        """
        if timeout not in range(5):
            raise ValueError("invalid timeout value")
        try:
            # timeout, picture type (unspecified), image size, major, minor
            pdata = struct.pack("<LLLLL", timeout, 0, len(image), 0, 0) + image
            self.__send_packet(cmd_PICTURE2, len(pdata), pdata)
            version, command, size = self.__unpack_header()
            if command == cmd_PICTURE_TEXT:
                data = self.__socket.recv(size)
                # timeout, type, size, major, minor
                __, __, __, major, minor = struct.unpack("<LLLLL", data[:self.__text_OFFSET])
                return Captcha(data[self.__text_OFFSET:], major, minor)
            else:
                raise DecaptcherError(command)
        except socket.timeout, e:
            self.__throw_network_error("socket timeout")
        except Exception, e:
            self.__throw_network_error("unknown exception (%s)" % e)

    def submit_bad_captcha(self, captcha=None, major=None, minor=None, timeout=timeout_DEFAULT):
        if not isinstance(captcha, Captcha) and (major is None or minor is None):
            raise ValueError("nothing to submit")
        if timeout not in range(5):
            raise ValueError("invalid timeout value")
        if major is None: major = captcha.major
        if minor is None: minor = captcha.minor
        # timeout, picture type (unspecified), size, major, minor
        pdata = struct.pack("<LLLLL", timeout, 0, 0, major, minor)
        self.__send_packet(cmd_PICTURE_FAIL, len(pdata), pdata)

    def logout(self):
        """
        Decaptcher.com logout function, closes socket connection.
        """
        try:
            self.__send_packet(cmd_BYE, 0)
            self.__socket.close()
            self.__socket = None
        except socket.timeout, e:
            self.__throw_network_error("socket timeout")
        except Exception, e:
            self.__throw_network_error("unknown exception (%s)" % e)

    def __throw_network_error(self, message):
        if self.__socket:
            self.__socket.close()
            self.__socket = None
        raise NetworkError(message)

    def __send_packet(self, command, size, data="", version=__api_VERSION):
        self.__socket.send(struct.pack("<BBL", version, command, size))
        if (data != ""):
            self.__socket.send(data)

    def __unpack_header(self):
        version, command, size = struct.unpack("<BBL", self.__socket.recv(6))
        if version != self.__api_VERSION:
            self.__throw_network_error("api version was changed")
        return (version, command, size)
