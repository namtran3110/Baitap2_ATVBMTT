# MÔN HỌC: AN TOÀN VÀ BẢO MẬT THÔNG TIN
## Họ và tên: ........................................................
## MSSV: ................................................................
## Lớp: ...................................................................

---

# BÀI 2: MÃ HÓA RSA, HÀM BĂM SHA-256 VÀ CHỮ KÝ SỐ

## 1. Mục tiêu bài tập

- Xây dựng ứng dụng desktop bằng C# Windows Forms (.NET), không sử dụng website.
- Tạo cặp khóa RSA, xuất và nhập khóa bằng định dạng PEM.
- Phân tích cấu trúc PEM, DER/ASN.1 và giải thích các tham số của khóa RSA.
- Mã hóa mảng byte có độ dài không quá 190 byte bằng RSA-OAEP-SHA256; lưu bản mã dưới dạng Base64, giải mã và so sánh dữ liệu.
- Đánh giá thời gian mã hóa, giải mã, ký và xác minh chữ ký RSA.
- Tạo giao diện tính SHA-256, quan sát sự thay đổi đầu ra khi dữ liệu đầu vào thay đổi ít.
- Sử dụng RSA-PSS kết hợp SHA-256 để tạo chữ ký số có tính ngẫu nhiên giữa các lần ký.

## 2. Công nghệ sử dụng

- Ngôn ngữ lập trình: C#.
- Nền tảng ứng dụng: Windows Forms trên .NET 8.
- Mã hóa dữ liệu: RSA-OAEP với SHA-256.
- Hàm băm: SHA-256.
- Chữ ký số: RSA-PSS kết hợp SHA-256.
- Đo thời gian: `Stopwatch`.
- Định dạng khóa: PEM; dữ liệu nhị phân bên trong được mã hóa theo DER/ASN.1.

## 3. Chức năng 1: Sinh cặp khóa RSA và xuất khóa PEM

<!-- 📸 CHÈN ẢNH 01: Giao diện tạo khóa RSA và trạng thái khóa sau khi sinh -->
![Ảnh 01 - Giao diện sinh cặp khóa RSA](images/01-sinh-cap-khoa-rsa.png)

- Cho phép chọn kích thước khóa RSA-2048, RSA-3072 hoặc RSA-4096.
- Sinh cặp khóa gồm khóa công khai (Public Key) và khóa bí mật (Private Key).
- Xuất khóa công khai ra tệp `khoa_cong_khai.pem` và khóa bí mật ra tệp `khoa_bi_mat.pem`.
- Khóa công khai được xuất theo cấu trúc SubjectPublicKeyInfo (`BEGIN PUBLIC KEY`); khóa bí mật được xuất theo PKCS#8 (`BEGIN PRIVATE KEY`).

--> Chức năng này đáp ứng yêu cầu tạo cặp khóa và lưu cặp khóa RSA ra tệp PEM. Khóa bí mật chỉ dùng cho thực hành và cần được giữ kín.

<!-- 📸 CHÈN ẢNH 02: Hai tệp PEM đã xuất, có thể mở bằng trình soạn thảo văn bản; không công khai khóa bí mật -->
![Ảnh 02 - Các tệp PEM đã xuất](images/02-tep-pem-da-xuat.png)

## 4. Chức năng 2: Nhập khóa PEM và kiểm tra cặp khóa

<!-- 📸 CHÈN ẢNH 03: Nhập khóa công khai và khóa bí mật, trạng thái báo cặp khóa khớp -->
![Ảnh 03 - Nhập khóa và kiểm tra cặp khóa](images/03-nhap-khoa-va-kiem-tra.png)

- Nhập khóa công khai và khóa bí mật từ các tệp PEM.
- Hiển thị trạng thái khóa đã nạp và kích thước khóa.
- Khi đã nạp cả hai khóa, ứng dụng thực hiện phép thử nội bộ để thông báo hai khóa có thuộc cùng một cặp hay không.
- Trường hợp cặp khóa không khớp, cần nhập lại đúng khóa trước khi mã hóa/giải mã hoặc ký/xác minh.

--> Việc kiểm tra cặp khóa giúp phát hiện sớm trường hợp chọn nhầm tệp khóa, tránh nhầm lẫn khi thử nghiệm.

## 5. Chức năng 3: Xem PEM và phân tích cấu trúc DER/ASN.1

<!-- 📸 CHÈN ẢNH 04: Nội dung PEM cùng kết quả phân tích cấu trúc DER/ASN.1 -->
![Ảnh 04 - Phân tích cấu trúc PEM](images/04-phan-tich-pem-der.png)

- Hiển thị nội dung PEM, nhãn `BEGIN/END`, số ký tự Base64 và độ dài dữ liệu DER sau khi giải mã Base64.
- Hiển thị cây cấu trúc ASN.1 theo từng trường, bao gồm offset byte, tag, độ dài phần header và độ dài phần dữ liệu.
- Hiển thị một phần dữ liệu DER dưới dạng HEX để quan sát byte thực tế.
- Đọc và giải thích các tham số RSA như `n`, `e`, `d`, `p`, `q`, `dp`, `dq`, `inverseQ` tùy theo loại khóa.

**Ý nghĩa các trường cơ bản:**

- `n`: mô-đun RSA, thành phần công khai chung của cặp khóa.
- `e`: số mũ công khai, thường có giá trị 65537.
- `d`: số mũ bí mật.
- `p`, `q`: hai số nguyên tố bí mật tạo nên `n`.
- `dp`, `dq`, `inverseQ`: tham số hỗ trợ tối ưu phép toán RSA bằng khóa bí mật.
- `SEQUENCE`, `INTEGER`, `BIT STRING`, `OCTET STRING`, `OBJECT IDENTIFIER`: các kiểu trường ASN.1 thể hiện trong dữ liệu DER.

--> PEM là dạng biểu diễn văn bản gồm nhãn và phần Base64. Base64 không phải mã hóa bảo mật; giải mã Base64 thu được dữ liệu DER nhị phân. Các offset hiển thị được tính từ byte 0 của DER, không phải vị trí ký tự trong văn bản PEM.

<!-- 📸 CHÈN ẢNH 05: Phân tích khóa công khai hiển thị n và e -->
![Ảnh 05 - Các tham số của khóa công khai](images/05-tham-so-khoa-cong-khai.png)

<!-- 📸 CHÈN ẢNH 06: Phân tích khóa bí mật hiển thị n, e, d và các tham số liên quan; chỉ dùng khóa thử nghiệm -->
![Ảnh 06 - Các tham số của khóa bí mật](images/06-tham-so-khoa-bi-mat.png)

## 6. Chức năng 4: Mã hóa dữ liệu bằng RSA

<!-- 📸 CHÈN ẢNH 07: Nhập một đoạn văn bản ngắn, hiển thị số byte UTF-8 và mã hóa thành Base64 -->
![Ảnh 07 - Mã hóa văn bản bằng RSA](images/07-ma-hoa-van-ban.png)

- Nhập dữ liệu nguồn dưới dạng văn bản UTF-8. Ứng dụng chuyển văn bản thành mảng byte trước khi mã hóa.
- Sử dụng khóa công khai đã tạo hoặc đã nhập từ PEM để mã hóa bằng RSA-OAEP-SHA256.
- Ứng dụng hiển thị độ dài dữ liệu theo byte, vì ký tự tiếng Việt có thể chiếm nhiều hơn một byte trong UTF-8.
- Với RSA-2048 và OAEP-SHA256, độ dài dữ liệu đầu vào tối đa là 190 byte theo công thức `mLen <= k - 2*hLen - 2`.

--> Giới hạn được tính theo số byte thực tế, không phải số ký tự. Dữ liệu vượt giới hạn sẽ bị từ chối.

<!-- 📸 CHÈN ẢNH 08: Tạo khóa AES-256 mẫu 32 byte và mã hóa mảng byte bằng khóa công khai RSA -->
![Ảnh 08 - Mã hóa khóa AES-256 mẫu](images/08-ma-hoa-khoa-aes-mau.png)

- Ứng dụng có chức năng tạo khóa AES-256 mẫu gồm 32 byte ngẫu nhiên và mã hóa chính mảng byte này bằng RSA.
- Chuỗi Base64 chỉ là cách biểu diễn khóa AES để hiển thị; RSA mã hóa mảng byte nhị phân 32 byte, không mã hóa chuỗi Base64 dài 44 ký tự.
- Có thêm ô nhập mảng byte tùy ý dạng Base64. Ví dụ `AAECAwQF` đại diện cho 6 byte `00 01 02 03 04 05`; chương trình giải mã Base64 thành `byte[]` rồi mã hóa mảng byte thực.
- Bản mã RSA được hiển thị ở dạng Base64 và có thể lưu ra tệp `.b64`.

<!-- 📸 CHÈN ẢNH 09: Tệp Base64 sau khi lưu, hiển thị tên và đường dẫn tệp -->
![Ảnh 09 - Lưu bản mã Base64](images/09-luu-ban-ma-base64.png)

## 7. Chức năng 5: Giải mã và so sánh dữ liệu

<!-- 📸 CHÈN ẢNH 10: Đọc tệp Base64, giải mã bằng khóa bí mật và hiển thị dữ liệu khôi phục -->
![Ảnh 10 - Giải mã bản mã RSA](images/10-giai-ma-ban-ma.png)

- Nạp khóa bí mật tương ứng từ PEM.
- Đọc bản mã Base64 từ ô dữ liệu hoặc từ tệp đã lưu.
- Chuyển Base64 về mảng byte bản mã, sau đó giải mã bằng RSA-OAEP-SHA256.
- Hiển thị dữ liệu khôi phục ở dạng Base64 và hiển thị UTF-8 nếu mảng byte là văn bản hợp lệ.
- So sánh từng byte của dữ liệu khôi phục với mảng byte nguồn trong phiên hiện tại. Nếu mở một bản mã cũ, có thể so sánh với văn bản nguồn đang nhập trên giao diện.

--> Kết quả `GIỐNG HỆT` chỉ được ghi nhận khi hai mảng byte có cùng độ dài và tất cả byte tương ứng đều giống nhau.

<!-- 📸 CHÈN ẢNH 11: Kết quả so sánh hiển thị GIỐNG HỆT -->
![Ảnh 11 - So sánh dữ liệu nguồn và dữ liệu giải mã](images/11-so-sanh-du-lieu.png)

## 8. Chức năng 6: Đo tốc độ các phép toán RSA

<!-- 📸 CHÈN ẢNH 12: Bảng kết quả đo tốc độ mã hóa, giải mã, ký và xác minh -->
![Ảnh 12 - Đo tốc độ RSA](images/12-do-toc-do-rsa.png)

- Chọn dữ liệu thử nghiệm có độ dài phù hợp và số lần lặp.
- Đo thời gian tổng và thời gian trung bình cho bốn phép toán: mã hóa bằng khóa công khai, giải mã bằng khóa bí mật, ký RSA-PSS và xác minh chữ ký.
- Ứng dụng kiểm tra cặp khóa và kết quả phép toán trước khi bắt đầu đo.
- Nên thực hiện nhiều lần trong cùng điều kiện, cùng máy, cùng kích thước khóa và cùng dữ liệu để kết quả có thể so sánh.

**Bảng số liệu thực nghiệm:**

| Kích thước khóa | Số lần lặp | Mã hóa (ms/lần) | Giải mã (ms/lần) | Ký (ms/lần) | Xác minh (ms/lần) |
|---|---:|---:|---:|---:|---:|
| RSA-2048 | 100 | Điền số liệu | Điền số liệu | Điền số liệu | Điền số liệu |
| RSA-3072 | 100 | Điền số liệu | Điền số liệu | Điền số liệu | Điền số liệu |

--> Số mũ công khai `e` thường nhỏ nên phép toán khóa công khai thường nhanh. Phép toán khóa bí mật sử dụng `d` thường có chi phí cao hơn. Kết luận cuối cùng cần dựa trên số liệu đo được trên máy thực tế.

## 9. Chức năng 7: Tính hàm băm SHA-256

<!-- 📸 CHÈN ẢNH 13: Hai dữ liệu chỉ khác một ký tự, hiển thị hai chuỗi SHA-256 -->
![Ảnh 13 - So sánh hai chuỗi băm SHA-256](images/13-so-sanh-sha256.png)

- Nhập dữ liệu A và dữ liệu B. Ứng dụng tự động tính lại kết quả SHA-256 khi nội dung thay đổi.
- SHA-256 luôn tạo đầu ra 256 bit, tương đương 32 byte hoặc 64 ký tự hex.
- Chương trình đếm số bit khác nhau giữa hai kết quả băm để đánh giá hiệu ứng avalanche.
- Với hai đầu vào khác nhau một lượng nhỏ, đầu ra thường thay đổi mạnh; khoảng 128/256 bit khác nhau là kỳ vọng thống kê, không phải quy tắc bắt buộc cho mọi cặp dữ liệu.

--> SHA-256 là hàm băm một chiều, không phải thuật toán mã hóa có thể giải mã ngược.

## 10. Chức năng 8: Tạo và xác minh chữ ký số RSA-PSS

<!-- 📸 CHÈN ẢNH 14: Ký cùng dữ liệu hai lần với cùng khóa bí mật, hai chữ ký khác nhau -->
![Ảnh 14 - Hai chữ ký RSA-PSS khác nhau](images/14-hai-chu-ky-khac-nhau.png)

- Nhập dữ liệu cần ký và tạo chữ ký bằng khóa bí mật với RSA-PSS kết hợp SHA-256.
- Ký lại đúng dữ liệu bằng cùng khóa bí mật. RSA-PSS sử dụng salt ngẫu nhiên nên chữ ký ở các lần ký có thể khác nhau.
- Dùng khóa công khai tương ứng để xác minh chữ ký.
- Sửa một ký tự trong dữ liệu rồi xác minh lại để kiểm tra chữ ký cũ không còn hợp lệ.

--> Điều kiện đạt là hai chữ ký của cùng dữ liệu có thể khác nhau, nhưng mỗi chữ ký vẫn xác minh thành công với dữ liệu ban đầu và khóa công khai tương ứng.

<!-- 📸 CHÈN ẢNH 15: Xác minh chữ ký hợp lệ với dữ liệu gốc -->
![Ảnh 15 - Xác minh chữ ký hợp lệ](images/15-xac-minh-chu-ky.png)

<!-- 📸 CHÈN ẢNH 16: Sửa dữ liệu sau khi ký và xác minh thất bại -->
![Ảnh 16 - Xác minh thất bại khi dữ liệu thay đổi](images/16-xac-minh-that-bai.png)

## 11. Tổng hợp kết quả kiểm thử

| STT | Nội dung kiểm thử | Kết quả thực tế |
|---:|---|---|
| 1 | Sinh cặp khóa RSA | Điền sau khi thực hiện |
| 2 | Xuất và nhập PEM khóa công khai/khóa bí mật | Điền sau khi thực hiện |
| 3 | Phân tích DER/ASN.1 và đọc tham số RSA | Điền sau khi thực hiện |
| 4 | Mã hóa và giải mã văn bản | Điền sau khi thực hiện |
| 5 | Mã hóa khóa AES-256 mẫu 32 byte | Điền sau khi thực hiện |
| 6 | Từ chối dữ liệu vượt giới hạn 190 byte với RSA-2048 | Điền sau khi thực hiện |
| 7 | So sánh dữ liệu nguồn và dữ liệu giải mã | Điền sau khi thực hiện |
| 8 | Đo tốc độ mã hóa/giải mã/ký/xác minh | Điền sau khi thực hiện |
| 9 | Quan sát thay đổi SHA-256 | Điền sau khi thực hiện |
| 10 | Ký hai lần cùng dữ liệu và xác minh chữ ký | Điền sau khi thực hiện |
| 11 | Thay đổi dữ liệu hoặc dùng khóa không đúng để xác minh | Điền sau khi thực hiện |

## 12. Kết luận

Qua bài tập, ứng dụng đã được xây dựng để minh họa các chức năng tạo và quản lý cặp khóa RSA, xử lý PEM, mã hóa/giải mã dữ liệu ngắn, tính SHA-256 và tạo chữ ký số RSA-PSS. Các kết luận về tốc độ và độ chính xác cần được hoàn thiện sau khi chạy kiểm thử trên máy thực tế.

- Kết quả so sánh dữ liệu sau giải mã: **[Điền kết quả thực tế]**.
- Phép toán RSA có thời gian trung bình thấp nhất: **[Điền từ bảng đo]**.
- Số bit khác nhau giữa hai chuỗi SHA-256 thử nghiệm: **[Điền kết quả thực tế]**.
- Kết quả ký hai lần với cùng dữ liệu và khóa: **[Điền kết quả thực tế]**.

> **Lưu ý bảo mật:** Không đưa khóa bí mật thật lên GitHub hoặc vào ảnh báo cáo. Khi chụp màn hình phần tham số khóa bí mật, chỉ sử dụng khóa sinh riêng cho bài thực hành và che thông tin nếu không cần thiết phải trình bày toàn bộ giá trị.

## 13. Tài liệu tham khảo

- RFC 7468 – Quy định cách biểu diễn văn bản PEM: https://www.rfc-editor.org/rfc/rfc7468.html
- RFC 8017 – Đặc tả mật mã RSA, bao gồm OAEP và PSS: https://www.rfc-editor.org/rfc/rfc8017.html
- Microsoft Learn – Nhập khóa từ PEM bằng `RSA.ImportFromPem`: https://learn.microsoft.com/en-us/dotnet/api/system.security.cryptography.rsa.importfrompem
- Microsoft Learn – Đệm chữ ký RSA-PSS: https://learn.microsoft.com/en-us/dotnet/api/system.security.cryptography.rsasignaturepadding.pss
