# export-cryptopro-certs
Экспортирует сертификаты КриптоПРО в json файл.

Флаги
```
-certmgr string
      certmgr лежит в <string> (default "/opt/cprocsp/bin/amd64/certmgr")
-expiring
      Экспортировать только истекающие сертификаты (default true)
-expiring-days int
      Считать сертификат истекающим за <int> дней до конца срок  (default 30)
-for-user string
      Сохранить вывод для пользователя <string> (default "zabbix")
-output string
      Сохранять вывод в <string> (default "/tmp/certs-info.json")
```

P.S. Зачем этот скрипт.
Настраивал мониторинг с zabbix, понадобилось мониторить сроки истекания сертификатов. На сервере сертификаты установлены для root, т.е. zabbix не имеет прав на их просмотр. По этому вместо плагина для zabbix я написал этот скрипт и добавил его в cron, а zabbix уже использует результат работы скрипта.
