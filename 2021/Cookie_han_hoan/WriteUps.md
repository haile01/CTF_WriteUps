# Write-up cookie hân hoan

> Some cringy quotes here

## Cryptography

### Xor

> XOR

```tex
# cipher.txt
6c464b4d514b744817491714487449174b57
```

```python
# encrypt.py
flag = ###SECRET###
key = ###SECRET###
assert len(key) == 1

def encrypt(a,b):
    return ''.join([hex(ord(b[i%len(b)]) ^ ord(a[i]))[2:] for i in range(0,len(a))])

with open('cipher.txt', 'w') as f:
        f.write(encrypt(flag, key))
```

Như thường lệ, điều đầu tiên của mình là xor thử với prefix xem đoán được key không

```python
cipher = open('cipher.txt', 'r').read().strip()
cipher = [chr(int(cipher[i:i+2], 16)) for i in range(0, len(cipher), 2)]
msg = 'Flag{'
key = ''
for i in range(len(msg)):
    key += chr(ord(cipher[i]) ^ ord(msg[i]))
   
print(key) # '*****'
```

Thế là ra flag :D

`Flag{a^b=c=>b^c=a}`

### Morse

> Suỵt! Tập trung và đeo tai nghe lên nào. Gà có nghe thấy nhịp beat không? Họ nói gì từ bên kia chiến tuyến Format: Flag{what_you_find}
>
> [cipher.wav](https://season1.cookiearena.org/files/4e876842996f6153f73c7bb3400ea7cb/cipher.wav)

File audio đính kèm chỉ đơn giản là morse thôi, quăng lên mấy tool online là xong, chẳng hạn như [đây](https://youtu.be/aCgP8BFjrw4) hoặc [đây](https://morsecode.world/international/decoder/audio-decoder-adaptive.html)

`Flag{M.O.R.S.E.C.O.D.E}`

### Jullius Caesar

> Vô tình khi khai quật khảo cổ, Gà tìm được một thông điệp bí ẩn khoảng hơn 100 năm trước công nguyên. Nghe đồn đây là một bí thuật đã bị thay đổi công thức của một vị tướng Julius Caesar, sau này trở thành vị vua đầu tiên của đế chế La Mã hùng mạnh.
>
> Hãy giúp Gà giải mật thư này!

```tex
# cipher.txt
Synt{Ry_Pynfvpb_Pvcure}
```

Ôi dồi, tool chạy phát là xong, lên [đây](https://www.dcode.fr/caesar-cipher) cũng được

`Flag{El_Clasico_Cipher}`

### Sixty Four

> Gà để lại một thông điệp bí mật nhưng nó không làm khó được trí thông minh của Mèo Yang Hồ.

```
cipher.txt
NDY2QzYxNjc3QjVGNUY1RjQyNjE3MzY1MzYzNDc4NDg2NTc4NUY1RjVGN0Q=
```

Rõ ràng là base64 rồi, decode ra được thế này

```
466C61677B5F5F5F426173653634784865785F5F5F7D
```

Ban đầu mình đoán là base32 nhưng bị lỗi, xong mới thấy chữ cái toàn A-F ( ͡° ͜ʖ ͡°)

Decode hex là xong

`Flag{___Base64xHex___}`

### Bruh AES

> Ôi không, Hazy lỡ xoá đi một mảnh ghép trong quá trình mã hoá AES mất rồi :)

## Web Exploitation

### XSS

> Các cậu còn nhớ sự kiện Livestream lần đầu tiên của Hazy , có một số bạn đã nghịch ngợm làm bay màu cái Chatbox. Đố bạn cho bay màu chal12 này đấy.

### XSS Filter

> Có vẻ như Chall12 là quá dễ với các bạn, thế còn lọc bớt một số kí tự thì sao :)

### Ét Quy Eo

> Đây là một lỗ hổng rất cơ bản nhưng lại dễ dàng bị bỏ qua trong quá trình phát triển ứng dụng.Lỗ hổng này nguy hiểm tới mức cho phép các h@cker lấy quyền quản trị của website, thay đổi nội dung, lợi dụng để ăn cắp các thông tin nhạy cảm, hoặc thậm chí làm bàn đạp tấn công chiếm quyền quản trị toàn hệ thống.
>
> Đây là phương thức tấn công yêu thích của Hacker khi lần đầu tiếp cận với website của bạn

### SQL Filter

### Gatling gun

> Với chiếc Gatling gun mạnh mẽ trong tay, Mèo Yang Hồ có thể vượt qua bất kì cánh cửa bảo mật nào. Nhưng thật buồn cười là trong tay hắn lại không có một viên đạn nào.Nếu bạn muốn nghịch súng với Mèo thì hãy đi nhặt đạn ở trong Github của Cookie Hân Hoan nhé.

### The maze runner

> Lạc vào một mê cung với vô vàn những chuỗi kí tự bí ẩn. Vừa chạy vừa phải nghĩ đâu mới manh mối giúp Gà thoát ra.Hãy giúp Gà một tay nhé?

### ID'OR1=1

> Một lỗ hổng rất cơ bản! Nhưng nếu nó xảy ra thì hậu quả rất khủng khiếp...

## Forensic

### AudiCaty

> Hazy gửi cho Gà một thông điệp bí mật, kèm một lời nhắn "Đừng vội vàng kết luận môt vấn đề, luôn phải để mắt thấy tai nghe"

Phản xạ thấy file audio là bật tool lên coi spectrogram rồi.

![audicaty_noise](audicaty_noise.png)

Tiếc là tiếng nói che mất 1 phần flag, nên mình dùng noise reduction trong Audition, vòila

![audicaty_noise](audicaty.png)

`Flag{No_Bullets_for_Player_001}`

### Basic Image

> Đố bạn biết bức ảnh này được nhắc tới bài viết nào trên Fanpage của Cookie Hân Hoan ấy. Hehe!

> \> file KB.jpg
>
> KB.jpg: JPEG image data, JFIF standard 1.02, resolution (DPI), density 96x96, segment length 16, Exif Standard: [TIFF image data, big-endian, direntries=5, manufacturer=Flag{metadataratatatataaaaaa}], progressive, precision 8, 2048x2048, components 3

### ExSeller

> Để không bị Mèo nhòm ngó tệp tài liệu quan trọng. Gà nhanh tay đặt mật khẩu, nhưng lại vô tình quên mất. Làm thế nào bây giờ T_T

Linh tính mách bảo là unzip nó ra đi, và đúng là có flag thật :D

> \> unzip bruteme.xlsx
>
> \> cat sharedStrings.xml
>
> <?xml version="1.0" encoding="UTF-8" standalone="yes"?>
> <sst xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" count="2" uniqueCount="2">
>   <si>
>     <t>check</t>
>   </si>
>   <si>
>     <t>Flag{Micro$oft_Heck3r_Man}</t>
>   </si>
> </sst>

### Streamer

> Anh nghệ sĩ nhiều đam mê đang vớt rác bên tàu. Ta lang thang với bản vẽ đời ta tự tô màu.Ô! Vớt được cái gì thú zị này!

Dùng wireshark này thì thấy có 1 file .zip được upload, lấy về rồi mở ra xem có gì nào. (Cách làm của mình là copy hex stream xong lưu lại, sau đó dùng python, **không phải python 3.8 trở đi nha**, để lưu binary).

![streamer](streamer.png)

Giải nén sẽ có file `flag.txt`. Done!

`Flag{TCP_streamin_go_skrrrrrrrt}`

### Interceptor

> Rối loạn tiền đình là bệnh lý gây ra trạng thái mất cân bằng về tư thế, khiến người bệnh thường xuyên bị chóng mặt, hoa mắt, ù tai, đi đứng lảo đảo.Nhưng sự thật não bạn đang muốn nhảy như điệu tanggo Khoan, dừng khoảng chừng là 2 giây!

Dùng bất kì tool nào để đọc được từng ảnh của file gif, 9 ảnh đầu sẽ có chứa 1 mảnh của mã QR, tách ra xong ghép lại là xong

![interceptor](interceptor.png)

`Flag{1s_th1s_m1sc3llan30us?}`

### Volatility

> *The true forenSeek*
>
> Giữ nguyên hiện trường là việc cần thiết trong quá trình điều tra số. Một trong những file lưu trữ hình ảnh của RAM trong quá trình làm đề thi được leak ra cho các chiến binh. Cho mình thấy các cậu tìm được gì nào :)

Dùng volatility để liệt kê các tiến trình thì thấy file `DumpIt.exe`, ngại gì không dump memory ra

>\> volatility imageinfo -v -f DESKTOP-K5GNI06-20211028-104628.raw
>
>\> volatility pslist -f DESKTOP-K5GNI06-20211028-104628.raw --profile=Win10x64_19041
>
>\> volatility memdump --dump-dir=./ -p 5932 -f DESKTOP-K5GNI06-20211028-104628.raw --profile=Win10x64_19041
>
>(5932 là pid của DumpIt.exe)

Sau đó mình dùng `strings` kiểm tra thử xem flag có đọc được liền không, hên là có =)))

`Flag{7ef31e58bd4086e294b4d700c721f35f}`

### Github

> Được biết tới như một kho lưu trữ mã nguồn khổng lồ của thế giới, và những thay đổi trong quá khứ đều được lưu lại và khôi phục. Hãy kiếm tìm những bí mật mà Gà con lon ton vô tình để lại.
>
> [https://github.com...](https://github.com/)

Sau 1 hồi tìm "Gà con lon ton" trên github không khả quan, mình thử tìm "Cookie hân hoan" thì thấy ngay cái cần tìm :D

Phiên bản mới nhất của main thì không có gì nổi bật, nhưng history thì lại xóa kha khá thứ, mò thì sẽ thấy flag thôi.

⢀⣠⣾⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠀⠀⠀⠀⣠⣤⣶⣶⣿⣿⣿⣿⣿⣿⣿⣿⣿

⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠀⠀⠀⢰⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿

⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣧⣀⣀⣾⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿

⣿⣿⣿⣿⣿⡏⠉⠛⢿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿

⣿⣿⣿⣿⣿⣿⠀⠀⠀⠈⠛⢿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠿⠛⠉⠁⠀⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿

⣿⣿⣿⣿⣿⣿⣧⡀⠀⠀⠀⠀⠙⠿⠿⠿⠻⠿⠿⠟⠿⠛⠉⠀⠀⠀⠀⠀⣸⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿

⣿⣿⣿⣿⣿⣿⣿⣷⣄⠀⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣴⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿

⣿⣿⣿⣿⣿⣿⣿⣿⣿⠏⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠠⣴⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿

⣿⣿⣿⣿⣿⣿⣿⣿⡟⠀⠀⢰⣹⡆⠀⠀⠀⠀⠀⠀⣭⣷⠀⠀⠀⠸⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿

⣿⣿⣿⣿⣿⣿⣿⣿⠃⠀⠀⠈⠉⠀⠀⠤⠄⠀⠀⠀⠉⠁⠀⠀⠀⠀⢿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿

⣿⣿⣿⣿⣿⣿⣿⣿⢾⣿⣷⠀⠀⠀⠀⡠⠤⢄⠀⠀⠀⠠⣿⣿⣷⠀⢸⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿

⣿⣿⣿⣿⣿⣿⣿⣿⡀⠉⠀⠀⠀⠀⠀⢄⠀⢀⠀⠀⠀⠀⠉⠉⠁⠀⠀⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿

⣿⣿⣿⣿⣿⣿⣿⣿⣧⠀⠀⠀⠀⠀⠀⠀⠈⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢹⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿

⣿⣿⣿⣿⣿⣿⣿⣿⣿⠃⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿

⣿⣿⣿Flag{no_where_to_hide_gitleaks}⣿⣿⣿⣿⣿⣿

⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿


## Network

### Post Office Man

> Anh bưu tá này là một người mà Gà rất tin tưởng. Gà ủy quyền cho anh ấy lên bưu điện, nói chuyện với anh kiểm thư để lấy thư về.
>
> Nếu giấy ủy quyền hợp lệ, anh kiểm thư sẽ giữ lại bản gốc rồi photocopy ra một bản khác để anh bưu tá đem về cho Gà. Để nhỡ trong trường hợp Gà có tức quá xé thư đi thì vẫn có thể lên đây lấy lại.
>
> Đố bạn anh bưu tá sử dụng giao thức email nào để nói chuyện với anh kiểm thư?
>
> `network.letspentest.org 9002`

Khi netcat lần đầu nó hiện thế này

>+OK popper file-based pop3 server ready
>
>Please using USER to login first
>Các Bạn hãy sử dụng câu lênh USER để login vào hệ thống
>(Cứ nhập linh tinh zô 乁| ･ 〰 ･ |ㄏ)

Chả hiểu gì, nên mình đi google 1 tí dựa trên cái phần mô tả kia và cái `pop3` trông đáng nghi thật sự

Sau đó thì mới biết cái giao thức đang nói tới là [POP](https://en.wikipedia.org/wiki/Post_Office_Protocol) (Post office protocol)

Sau đó mình cứ xài thử mấy lệnh có trong code mẫu, `LIST` là để liệt kê mail, còn `RETR <id>` là đọc nội dung của mail `<id>`, flag nằm ở mail 8

`Flag{1-Ha\/3-1o0o-UnS33n-3Ma1L}`

### Very Good Shipper

> Hãy tham gia đấu trường Cookie phiên bản nhanh như chớp. Gà phải chọn ra đáp án đúng trong thời gian nhanh nhất.
>
> Giao thức TCP sẽ giúp các câu trả lời của Gà luôn được đảm bảo gửi đến máy chủ của Cookie Arena mà không bị rơi rớt một từ nào.
>
> Tuy nhiên, Gà đã quên cổng kết nối vào máy chủ. Chỉ nhớ mang máng là nó giống với thử thách "Scan me if you can"
>
> `network.letspentest.org`

Lúc làm bài này thì mình chưa làm scan me if you can, nhưng cái từ "scan" lộ quá rồi còn gì

>\> nmap network.letspentest.org
>
>Host is up (0.051s latency).
>rDNS record for 18.139.222.220: ec2-18-139-222-220.ap-southeast-1.compute.amazonaws.com
>Not shown: 996 closed ports
>PORT     STATE SERVICE
>80/tcp   open  http
>7000/tcp open  afs3-fileserver
>9002/tcp open  dynamid
>9003/tcp open  unknown

Vì port 9002 làm bài Post office man rồi nên thử 9003. Hóa ra nó là giải đố vui vẻ thôi, trả lời đúng 6 câu trong kịp thời gian sẽ có flag

`Flag{t00-ez-4-y0u}`

### Where is my house?

> DNS CHÍNH LÀ XƯƠNG SỐNG CỦA INTERNET.
>
> Tên miền hay Domain chính là địa chỉ trang web, thứ mà các bạn vẫn hay gõ vào trên thanh địa chỉ trên trình duyệt để đọc báo hay lướt web, xem phim.
>
> Trên Internet mọi máy tính, máy chủ, các thiết bị mạng được kết nối và giao tiếp với nhau thông qua hệ thống cáp mạng chằng chịt và khổng lồ. Các máy tính sẽ được gán cho nhau những dãy số để định danh với nhau gọi là địa chỉ IP. Nói một cách dễ hiểu thì một ai đó muốn ghé thăm nhà bạn thì họ cần phải có địa chỉ nhà. Những dãy số địa chỉ này có độ dài có thể lên đến 12 hoặc 45 kí tự.
>
> Đến mật khẩu 6 kí tự bạn còn không nhớ nổi, vì thế năm 1984 DNS (Domain Name System) được phát minh để giúp bạn kết nối với nhau bằng tên gọi.
>
> Bạn chỉ cần nhớ letspentest.org thay vì những dãy số khô khan và kì quặc. Khi vừa Enter, hệ thống DNS bắt đầu hoạt động, nó như tấm bản đồ để chỉ cho bạn biết "Hey, cái tên miền của Cookie có địa chỉ IP là X.X.X.X, hãy tới đó mà lấy thông tin đê". DNS cũng trả lời cho bạn biết "X.X.X.X có phải địa chỉ nhà Cookie Hân Hoan hay không"
>
> DNS cũng chứa các thông tin khác, nó gọi là các bản ghi (Record). Bạn thử tìm xem domain này còn có những bản ghi nào chứa những điều kì quặc không?
>
> `letspentest.org`

Có vẻ đề cũng đã rõ, tìm các record của dns này, có nhiều tool làm được trò đó như [đây](https://dnsdumpster.com/) hoặc [đây](https://www.youtube.com/watch?v=aW0DRWhdZyY)

Flag nằm trong txt record

`Flag{DNS_A_AAAA_TXT_CNAME}`

### Scan me if you can

> Nếu coi mỗi máy chủ là một ngôi nhà, trước khi xâm nhập vào bên trong, các Hacker phải thực hiện việc thăm dò. Họ xem xét đâu là điểm yếu nhất của ngôi nhà, chỗ nào là điểm mù camera? Chủ nhà hoặc bảo vệ sẽ phản ứng thế nào khi có xuất hiện các dấu hiệu bất thường?
>
> Trong quá trình tìm kiếm lỗ hổng, Hazy thường xem xét ngôi nhà này có bao nhiêu cánh cửa đang mở (Port). Hãy sử dụng công cụ thân quen để "ném đá" vào tất cả các cánh cửa của ngôi nhà.
>
> Biết rằng, cửa sổ được đánh số từ 8100 tới 9100
>
> Dựa vào sự phản hồi bạn sẽ biết được những điều thú vị!
>
> `network-insecure.letspentest.org`

Rephrase lại đề: check xem ở domain này có cổng nào thú vị từ 8100 tới 9100

> \> nmap -p 8100-9100 network-insecure.letspentest.org
>
> Host is up (0.039s latency).
> rDNS record for 18.140.65.99: ec2-18-140-65-99.ap-southeast-1.compute.amazonaws.com
> Not shown: 999 closed ports
> PORT     STATE  SERVICE
>
> 9003/tcp open   unknown
> 9004/tcp open   unknown

Hmm, netcat cả 2 không được nên curl thử

> \> curl -v 18.140.65.99:9004
>
> \* Trying 18.140.65.99:9004...
>
> \* TCP_NODELAY set
>
> \* Connected to 18.140.65.99 (18.140.65.99) port 9004 (#0)
>
> \> GET / HTTP/1.1
> \> Host: 18.140.65.99:9004
> \> User-Agent: curl/7.68.0
> \> Accept: */*
>
> \* Mark bundle as not supporting multiuse
> < HTTP/1.1 400 Bad Request
> < Server: Flag{Every-Header-Have-It-Own-Meaning}Date: Wed, 03 Nov 2021 16:03:39 GMT
> < Content-Type: text/html
> < Content-Length: 255
> < Connection: close
> <
>
> <html>
>
> <head><title>400 The plain HTTP request was sent to HTTPS port</title></head>
>
> <body>
>
> <center><h1>400 Bad Request</h1></center>
> <center>The plain HTTP request was sent to HTTPS port</center>
> <hr><center>nginx/1.20.0</center>
> </body>
> </html>

Yay flag trong header rồi

### Secure HTTP

> HTTP và HTTPS đều là hai giao thức giúp trình duyệt của bạn truy cập, tương tác với các trang Web. Tuy nhiên khi sử dụng giao thức HTTP để truy cập Web ở một quán cà phê hay trong cùng một khu trọ thì tất cả các nội dung trao đổi nhạy cảm, cũng như mật khẩu của bạn trên Web đều có thể nghe lén.
>
> Còn HTTPS (chữ S có nghĩa là Secure - Bảo mật) sinh ra để mã hóa dữ liệu trong quá trình trao đổi giữa trình duyệt và máy chủ bằng một chiếc Chứng chỉ (Certificate)
>
> `network-insecure.letspentest.org 9004`

Do nãy giờ nmap nên cũng biết ip của domain này là `18.140.65.99`, nên curl thử

>\> curl -v https://18.140.65.99:9004
>
>...
>
>curl failed to verify the legitimacy of the server and therefore could not
>establish a secure connection to it

Có vẻ trang cấp 1 cái certificate hơi chuối nên curl không cho qua, đọc hướng dẫn sử dụng thì có thể thêm `--insecure` để "kệ" cái lỗi đó

> \> curl --insecure -v https://18.140.65.99:9004
>
> ...
>
> \* Server certificate:
>
> \* subject: C=VN; ST=Chicken-Little; L=Pussy-Cat; O=Flag{This-Is-A-Trusted-One}; OU=https://fb.com/cookie.han.hoan; CN=https://discord.gg/cookiehanhoan; emailAddress=Cookiehanhoan@gmail.com

Hehe, ezpz

## Programming

### SUM()

> Bỏ qua tất cả các tích phân, đạo hàm, ma trận, sác xuất. Gà hãy kết nối tới máy chủ của Cookie Arena và thực hiện tính tổng của dãy số đã cho một cách nhanh nhất.
>
> Hãy học cách sử dụng Python và player.py để giải toán nha
>
> `programming.letspentest.org 8111`

Cơ bản là bài này chỉ cần tính tổng các số được in ra.

`Flag{1plust1_1s_2_qu1ck_mafth}`

### Pro102

> Rồi một ngày kia mắt anh tròn xoe như đường tròn lượng giác Khi bất ngờ một bài toán bậc 2 Cứ lầm tưởng rằng nghiệm duy nhất với ai Thật kinh hoàng phương trình vô nghiệm
>
> (st)
>
> `programming.letspentest.org 8222`

Bài này thì tính nghiệm phương trình bậc 2, và đảm bảo là nghiệm nguyên.

`Flag{2fast2fur10us}`

### Roberval

> Hazy ngồi cân những viên bi mình đang có, loay hoay vẫn không biết phải cân bao nhiêu lần để tìm được viên bi nhẹ nhất.
>
> Bạn giúp Hazy một tay với nhé.
>
> `programming.letspentest.org 8333`

Google công thức thì nó là $\lceil log_3{n} \rceil$

`Flag{n0_pr0b_w1th_cub3_r00t_RIGHT?}`

## Web Basic

### Hân Hoan

> Thấy hộp bánh quy của chú Hazy để hớ hênh trên bàn. Với bản tính nghịch ngợm, Mèo Yang Hồ nhanh tay thêm chút gia vị để biến cuộc đời trở nên hài hước và hân hoan hơn.

### Header 401

> Để nhiều loại Trình duyệt và Web Server có thể nói chuyện và hiểu được nhau thì họ phải sử dụng chung một giao thức có tên gọi là HTTP Protocol. Khi người dùng bắt đầu truy cập Web, trình duyệt sẽ chuyển những hành động của họ thành yêu cầu (Request) tới Web Server. Còn Web Server sẽ trả lời (Response) xem có thể đáp ứng hay từ chối cung cấp thông tin cho trình duyệt.
>
> Ví dụ, bạn Gà muốn LẤY danh sách các thử thách trong cookiearena<chấm>org, ở đường dẫn /challenges bằng TRÌNH DUYỆT Chrome. Trình duyệt của Gà sẽ phải điền vào một cái form mẫu có tên gọi là HTTP Header và gửi đi. Mỗi yêu cầu sẽ được viết trên một dòng, và nội dung của mỗi yêu cầu sẽ phải viết đằng sau dấu hai chấm.
>
> Hãy đoán xem trong thử thách này có những Header thú vị nào nha

### JS B\*\*p B\*\*p

> Sau nhiều đêm suy nghĩ về việc làm thế nào để bảo vệ mã nguồn. Cố gắng thoát khỏi ánh mắt soi mói của Mèo Yang Hồ.
>
> Gà chẹp miệng rồi nói: "Đã tới lúc phải cho nó phải thốt lên rằng! WTF!!!"

### Impossible

> Học lỏm được công thức chế tạo lá chắn tàng hình của Hazy. Gà nhanh chóng đem về xây dựng hệ thống phòng thủ của riêng mình. Liệu nó có làm khó được Mèo Yang Hồ không?

### Infinite Loop

> Cuộc đời luôn là vậy. Một giây trước tưởng đã cùng đường, một giây sau có lại đầy hy vọng. Các chiến binh đã có công cụ mạnh mẽ trong tay, hãy dùng nó để can thiệp dòng chảy.

### I am not a robot

> Nếu là người thì cho xem tai, còn nếu là robot thì đứng ở ngoài. Bạn đã bị chặn

### Sause

> Trình duyệt đang rất vất vả để chuyển đổi các đoạn mã thành hình ảnh và màu sắc. Hãy trải nghiệm góc nhìn của trình duyệt nhé!