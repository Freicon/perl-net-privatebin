# Net::PrivateBin

Perl API Interface for PrivateBin.

### Working

Creating new pastes with many options. Use _net-privatebin-example.pl_ as a starting point.

Use "encode_and_post()" and "get_and_decode()" methods. They take 1 or 0 as argument to skip https verify or not (Default is 0).  

#### Options

| Name        | Default value | Possible values                                       | Description                           | Method            |
|-------------|---------------|-------------------------------------------------------|---------------------------------------|-------------------|
| burn        | 1             | 0, 1                                                  | burn after reading                    | set_burn()        |
| url         |               |                                                       |                                       | set_url()         |
| text        |               |                                                       |                                       | set_text()        |
| compression | zlib          | zlib, none                                            |                                       | set_compression() |
| discussion  | 0             | 0, 1                                                  | allow discussion                      | set_discussion()  |
| formatter   | plaintext     | plaintext, syntaxhighlighting, markdown               |                                       | set_formatter()   |
| password    |               |                                                       | password for encryption, (not needed) | set_password()    |
| attachment  |               |                                                       |                                       | set_attachment()  |
| debug       | 0             | 0, 1                                                  |                                       | set_debug()       |
| expire      | 1day          | 5min, 10min, 1hour, 1day, 1week, 1month, 1year, never |                                       | set_expire()      |



### ToDo

- Documentation
- Tests
- Test get method
- ...
