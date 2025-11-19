Python packages needed for this code to run include:

pysnmp
manuf
paramiko
scp
tzlocal
mac-vendor-lookup

And if you use the NetFlow collector:
netflow-parser

pip install pysnmp manuf mac-vendor-lookup paramiko scp tzlocal netflow-parser

If you do not use NetFlow, simply omit netflow-parser