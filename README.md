# gfwlist2pac
https://github.com/clowwindy/gfwlist2pac Java版


# build
mvn clean package


# run
java -jar gfwlist2pac-1.0-jar-with-dependencies.jar -o proxy.pac -p "SOCKS5 127.0.0.1:1080; SOCKS 127.0.0.1:1080; DIRECT;"



# 附录
## gfwlist 文件语法
```
! 用户自定义的代理规则
!
! 语法与gfwlist相同，即AdBlock Plus过滤规则
!
! 简单说明如下：
! 通配符支持，如 *.example.com/* 实际书写时可省略* 如.example.com/ 意即*.example.com/*
! 正则表达式支持，以\开始和结束， 如 \[\w]+:\/\/example.com\
! 例外规则 @@，如 @@*.example.com/* 满足@@后规则的地址不使用代理
! 匹配地址开始和结尾 |，如 |http://example.com、example.com|分别表示以http://example.com开始和以example.com结束的地址
! || 标记，如 ||example.com 则http://example.com、https://example.com、ftp://example.com等地址均满足条件
! 注释 ! 如 ! Comment
!
! 更详细说明 请访问 http://adblockplus.org/en/filters
!
! 配置该文件时需谨慎，尽量避免与gfwlist产生冲突，
! 或将一些本不需要代理的网址添加到代理列表
! 可用test目录工具进行网址测试
!

! Tip: 在最终生成的PAC文件中，用户定义规则先于gfwlist规则被处理
!      因此可以在这里添加一些常用网址规则，或能减少在访问这些网址进行查询的时间
!      如:
@@sina.com
@@163.com
twitter.com
youtube.com
```