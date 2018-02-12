#!/usr/bin/env python

from __future__ import print_function

from argparse import ArgumentParser
from logging import getLogger
from struct import unpack
from zipfile import ZipFile


BLOCK_MAGIC_NUM = b'\x55\xAA\x5A\xA5'

UNLOCK_CODE = b'HW8953\xff\xff'

MODULE_MAGIC_TABLE = {
  b'\x00\x00\x00\x00': 'SYSTEM',
  b'\x00\x00\x00\x40': 'RECOVERY',
  b'\x00\x00\x00\x44': 'ERECOVERY',
  b'\x00\x00\x00\x70': 'CUST',
  b'\x00\x00\x00\xA1': 'DSP',
  b'\x00\x00\x00\xA2': 'CMNLIB',
  b'\x00\x00\x00\xA3': 'KEYMASTER',
  b'\x00\x00\x00\xA4': 'MDTP',
  b'\x00\x00\x00\xA5': 'APDP',
  b'\x00\x00\x00\xA6': 'MSADP',
  b'\x00\x00\x00\xAA': 'CMNLIB64',
  b'\x00\x00\x00\xAB': 'DEVCFG',
  b'\x00\x00\x00\xAC': 'LKSECAPP',
  b'\x00\x00\x00\xC1': 'MODEM',
  b'\x00\x00\x00\xC2': 'RPM',
  b'\x00\x00\x00\xC3': 'TZ',
  b'\x00\x00\x00\xC6': 'SBL1',
  b'\x00\x00\x00\xD2': 'GPT',
  b'\x00\x00\x00\xE3': 'ABOOT',
  b'\x00\x00\x00\xE8': 'OEMSBL_VERLIST',
  b'\x00\x00\x00\xE9': 'OEMSBL_VER',
  b'\x00\x00\x00\xEA': 'AMSS_VERLIST',
  b'\x00\x00\x00\xEC': 'AMSS_VER',
  b'\x00\x00\x00\xFC': 'BOOT',
  b'\x00\x00\x00\xFE': 'SHA256RSA',
  b'\x00\x00\x00\xFF': 'CRC',
  b'\x13\x00\x00\x00': 'VENDOR',
  b'\x14\x00\x00\x00': 'VERSION',
  b'\x15\x00\x00\x00': 'PRODUCT',
  b'\xF2\xFF\xFF\xFF': 'PACKAGE_TYPE',
}


def format_hex(s):
  return ''.join('{:02x}'.format(c) for c in s)


def get_update_app_from_zip(zip_path):
  with ZipFile(zip_path) as update_zip:
    return update_zip.open('UPDATE.APP')


class UpdateAppParser:
  
  def __init__(self, update_app, logger=getLogger('UpdateAppParser')):
    self.update_app = update_app
    self.logger = logger


  def parse(self):
    # TODO: figure out what this null padding in the beginning is.
    null_padding = self.update_app.read(92)
    assert null_padding == b'\x00' * 92

    while True:
      self.update_app = self.parse_block()
      if self.update_app is None:
        break


  def parse_block(self):
    magic_num = self.update_app.read(4)
    if magic_num == b'': # EOF
      return None
    assert magic_num == BLOCK_MAGIC_NUM, 'dwMagicNum not found! 0x{}'.format(format_hex(magic_num))

    header_len_bytes = self.update_app.read(4)
    header_len_int = unpack('<L', header_len_bytes)[0]
    self.logger.debug('header_len = {}'.format(header_len_int))

    unknown1 = self.update_app.read(4) # TODO?
    assert unknown1 == b'\x01\x00\x00\x00', 'unknown1 not 0x01'
    self.logger.debug(format_hex(unknown1))

    unlock_code = self.update_app.read(8)
    assert unlock_code == UNLOCK_CODE, 'unlock_code incorrect'

    # nei data_start_addr
    module_id = self.update_app.read(4)
    self.logger.debug('module_id = 0x{}'.format(format_hex(module_id)))

    data_len = self.update_app.read(4)
    data_len_int = unpack('<L', data_len)[0]
    self.logger.debug('data_len = 0x{:08x}'.format(data_len_int))
    
    date = self.update_app.read(16)
    date_str = unpack('16s', date)[0].strip(b'\x00').decode('utf-8')
    self.logger.debug(date_str)

    time = self.update_app.read(16)
    time_str = unpack('16s', time)[0].strip(b'\x00').decode('utf-8')
    self.logger.debug(time_str)

    display_name = self.update_app.read(32)
    display_name_str = unpack('32s', display_name)[0].strip(b'\x00').decode('utf-8')
    self.logger.debug(display_name_str)

    unknown2 = self.update_app.read(2) # TODO: ?
    self.logger.debug(format_hex(unknown2))
    
    block_size = self.update_app.read(2) # TODO: Verify these are parsed right
    block_size_int = unpack('<H', block_size)[0]
    self.logger.debug('block_size = 0x{:04x}'.format(block_size_int))
    
    block_size_hw = self.update_app.read(2) # TODO: Verify these are parsed right
    block_size_hw_int = unpack('<H', block_size_hw)[0]
    self.logger.debug('block_size_hw = 0x{:04x}'.format(block_size_hw_int))

    unknown3 = self.update_app.read(2) # TODO: ?
    self.logger.debug(format_hex(unknown3))
    
    remaining_header_len = header_len_int - (4 + 4 + 4 + 8 + 4 + 4 + 16 + 16 + 32 + 2 + 2 + 2 + 2)
    if remaining_header_len:
      remaining_header = self.update_app.read(remaining_header_len)
      self.logger.debug('remaining_header_len = {}'.format(remaining_header_len))
      
    # Call the hooks
    self.on_header(
        unlock_code,
        module_id,
        date_str,
        time_str,
        display_name_str,
        block_size_int,
        block_size_hw_int,
        )
    
    self.on_data(self.update_app.read(data_len_int))

    alignment_padding = (4 - ((data_len_int + remaining_header_len) % 4)) % 4
    self.logger.debug(alignment_padding)
    if alignment_padding:
      self.logger.debug('Seeking 0x{:08x} ahead'.format(alignment_padding))
      self.update_app.read(alignment_padding)
    
    return self.update_app


  def on_header(self,
      unlock_code,
      module_id,
      date_str,
      time_str,
      display_name_str,
      block_size_int,
      block_size_hw_int,
      ):
    None


  def on_data(self, data):
    None


class DumpingParser(UpdateAppParser):

  def on_header(self,
      unlock_code,
      module_id,
      date_str,
      time_str,
      display_name_str,
      block_size_int,
      block_size_hw_int,
      ):
    self.last_module_id = module_id
    self.name = MODULE_MAGIC_TABLE[module_id].lower()
    assert self.name == display_name_str.lower()


  def on_data(self, data):
    open('{}'.format(self.name), 'wb').write(data)


if __name__ == '__main__':
  argparser = ArgumentParser(
      description='Work with Huawei UPDATE.APP (and update.zip) files.')
  argparser.add_argument(
      'update_file',
      help='Should be an UPDATE.APP file, or an update.zip with an UPDATE.APP in it.')
  args = argparser.parse_args()

  update_file_path = args.update_file
  
  if update_file_path.endswith('.zip'):
    update_app = get_update_app_from_zip(update_file_path)
  elif update_file_path.endswith('.APP'):
    update_app = open(update_file_path, 'rb')
  else:
    raise 'Unrecognised file name.'
  
  parser = DumpingParser(update_app)
  parser.parse()
