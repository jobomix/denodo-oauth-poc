import pyodbc
cnxn = pyodbc.connect('Driver=/opt/microsoft/msodbcsql17/lib64/libmsodbcsql-17.10.so.2.1;Server=tcp:postitdev-db1.database.windows.net,1433;Database=Db1;Uid=brunoa@positdev.co.uk;Pwd=Guimauve75!;Encrypt=yes;TrustServerCertificate=yes;Connection Timeout=30;Authentication=ActiveDirectoryPassword')
