# update_app.py

update_app.py is a tiny tool for working with Huawei `UPDATE.APP` and
`update.zip` files.

The main (in fact, currently, only) function is to extract ROM images from the
official stock ROMs.

If you've already got an `update.zip` file you extract all the contained images
by simply:

`update_app.py update.zip`

Depending on what the particular `UPDATE.APP` contains, you'll get files like
`system`, `boot`, `recovery`, and so on, extracted into the folder.
You'll also get several files that aren't really files as much as metadata.

The extracted images can then be flashed onto your device:
```
adb reboot bootloader
fastboot erase system 
fastboot flash system system
```


## Warning

Obviously, use this at your own risk.
You might well brick your device in the process.
