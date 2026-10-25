# Bài tập 2 – Mã hóa RSA, SHA-256 và chữ ký số

## 1. Mục tiêu

Ứng dụng desktop C# Windows Forms này phục vụ các yêu cầu của Bài 2 môn **An toàn và Bảo mật thông tin**. Đây là ứng dụng Windows, không phải website. Toàn bộ nhãn, hướng dẫn và thông báo do ứng dụng tạo ra sử dụng tiếng Việt có dấu; các tên thuật toán và định dạng như RSA, PEM, Base64, DER, ASN.1, SHA-256 được giữ nguyên theo quy ước kỹ thuật.

Các chức năng chính:

- Sinh cặp khóa RSA, xuất khóa công khai và khóa bí mật ra tệp PEM.
- Nhập khóa từ PEM, xem trạng thái khóa, phân tích cấu trúc PEM/DER và các tham số RSA.
- Mã hóa mảng byte bằng RSA-OAEP-SHA256, lưu bản mã dưới dạng Base64 và đọc lại từ tệp.
- Giải mã bằng khóa bí mật và so sánh mảng byte sau giải mã với dữ liệu nguồn trong phiên làm việc.
- Đo thời gian mã hóa, giải mã, ký và xác minh chữ ký RSA.
- Tính SHA-256 tự động khi thay đổi dữ liệu; đếm số bit khác nhau giữa hai chuỗi băm.
- Tạo và xác minh chữ ký RSA-PSS + SHA-256; kiểm tra cùng dữ liệu/cùng khóa có thể tạo chữ ký khác nhau ở các lần ký.

## 2. Công nghệ sử dụng

- C# và Windows Forms.
- .NET 8 (`net8.0-windows`).
- `System.Security.Cryptography.RSA` để xử lý RSA và PEM.
- RSA-OAEP với SHA-256 để mã hóa dữ liệu.
- SHA-256 để băm dữ liệu.
- RSA-PSS với SHA-256 để ký và xác minh chữ ký.
- `Stopwatch` để đo thời gian thực nghiệm.

> **Lưu ý về .NET:** Dự án hiện nhắm đến .NET 8. Nếu Visual Studio trên máy có .NET 8 SDK, có thể giữ nguyên cấu hình. .NET 8 dự kiến hết hỗ trợ ngày 10/11/2026; nếu môi trường có .NET 10 SDK, có thể chuyển `TargetFramework` trong `.csproj` thành `net10.0-windows`.

## 3. Mở và chạy chương trình

1. Giải nén `Bai2_MaHoaRSA.zip` vào thư mục dễ tìm, ví dụ `D:\BaiTap_ATBMTT\Bai2_MaHoaRSA`.
2. Mở Visual Studio.
3. Chọn **Open a project or solution** và mở `Bai2_MaHoaRSA.sln`.
4. Đảm bảo đã cài workload **.NET desktop development** cùng SDK phù hợp.
5. Nhấn `F5` để chạy ứng dụng.

Cách nhanh hơn: chạy tệp `RUN_WINDOWS.cmd` trong thư mục đã giải nén. Tệp này gọi `dotnet run` cho dự án; nếu thiếu .NET SDK, cửa sổ sẽ báo để bạn cài đặt.

Có thể biên dịch bằng Terminal tại thư mục chứa `.csproj`:

```powershell
dotnet restore
dotnet build
dotnet run
```

Nếu thiếu SDK, kiểm tra bằng lệnh `dotnet --list-sdks` và cài đặt SDK tương thích.

## 4. Hướng dẫn các chức năng

### 4.1. Tạo cặp khóa và xuất PEM

- Chọn kích thước 2048, 3072 hoặc 4096 bit.
- Chọn **Sinh cặp khóa** để tạo cặp RSA.
- Chọn **Xuất PEM khóa công khai** để lưu public key, mặc định gợi ý `khoa_cong_khai.pem`.
- Chọn **Xuất PEM khóa bí mật** để lưu private key, mặc định gợi ý `khoa_bi_mat.pem`.
- Khóa công khai được xuất theo SubjectPublicKeyInfo (`BEGIN PUBLIC KEY`); khóa bí mật được xuất theo PKCS#8 (`BEGIN PRIVATE KEY`).

Với yêu cầu giới hạn dữ liệu 190 byte, dùng RSA-2048 và OAEP-SHA256. Với khóa 3072/4096 bit, giới hạn OAEP cao hơn nhưng ứng dụng vẫn áp dụng giới hạn 190 byte theo yêu cầu bài tập.

### 4.2. Nhập khóa từ PEM

- Chọn **Nhập khóa công khai...** và chọn tệp PEM khóa công khai.
- Chọn **Nhập khóa bí mật...** và chọn tệp PEM khóa bí mật.
- Trạng thái giao diện cho biết khóa đã được nạp hay chưa và kích thước khóa.
- Khi đã có cả hai khóa, ứng dụng thực hiện phép thử mã hóa/giải mã một dữ liệu ngẫu nhiên ngắn để xác định hai khóa có thuộc cùng một cặp hay không; kết quả được hiển thị ngay ở trạng thái khóa.
- Có thể nhập hai khóa từ hai tệp riêng. Hai khóa cần thuộc cùng một cặp để giải mã hoặc xác minh chữ ký thành công.

**Bảo mật:** Khóa bí mật phải được giữ an toàn. Không gửi tệp PEM khóa bí mật cho người khác, không đưa lên GitHub công khai và không chụp ảnh để lộ toàn bộ khóa bí mật trong báo cáo. Chỉ dùng khóa tạo cho mục đích thực hành.

### 4.3. Xem PEM và ý nghĩa cấu trúc

PEM là cách đóng gói dữ liệu mật mã dưới dạng văn bản. Một tệp PEM thường gồm dòng mở đầu, dữ liệu Base64 và dòng kết thúc.

Base64 không phải mã hóa và không làm dữ liệu trở nên bí mật. Khi giải mã phần thân Base64, ta thu được dữ liệu DER được mã hóa theo ASN.1. DER gồm các trường tag, length và value (TLV), vì vậy độ dài/vị trí trường có thể thay đổi tùy loại khóa và kích thước khóa.

Các nhãn PEM được hỗ trợ:

| Nhãn PEM | Cấu trúc | Ý nghĩa chính |
|---|---|---|
| `PUBLIC KEY` | SubjectPublicKeyInfo (SPKI) | Bao gồm thông tin thuật toán và BIT STRING chứa RSAPublicKey (`n`, `e`). |
| `RSA PUBLIC KEY` | PKCS#1 RSAPublicKey | Chứa hai số nguyên `n` và `e`. |
| `PRIVATE KEY` | PKCS#8 PrivateKeyInfo | Bao ngoài chứa thông tin thuật toán và OCTET STRING chứa dữ liệu khóa bí mật. |
| `RSA PRIVATE KEY` | PKCS#1 RSAPrivateKey | Chứa `n`, `e`, `d`, `p`, `q`, `dp`, `dq`, `inverseQ` và các trường liên quan. |

Cửa sổ phân tích PEM hiển thị nhãn PEM, số byte DER, một phần byte DER ở dạng HEX, cây cấu trúc TLV có vị trí byte/mã thẻ/độ dài/ý nghĩa trường và các tham số RSA do thư viện đọc được. `n` là mô-đun; `e` là số mũ công khai; `d` là số mũ bí mật; `p`, `q` là các số nguyên tố bí mật; `dp`, `dq`, `inverseQ` hỗ trợ tối ưu phép toán khóa bí mật. Offset được tính từ byte đầu tiên của DER sau khi giải mã Base64.

Ứng dụng mẫu chưa hỗ trợ nhập khóa bí mật được mã hóa bằng mật khẩu (`ENCRYPTED PRIVATE KEY`).

### 4.4. Mã hóa mảng byte và lưu Base64

- Nhập văn bản UTF-8 rồi chọn **Mã hóa văn bản**. Chương trình chuyển văn bản thành mảng byte UTF-8 và mã hóa bằng khóa công khai.
- Chọn **Tạo khóa AES-256 mẫu (32 byte)** để tạo mảng byte ngẫu nhiên 32 byte, tương ứng độ dài khóa AES-256.
- Chọn **Mã hóa khóa AES mẫu** để mã hóa đúng 32 byte nhị phân bằng khóa công khai RSA. Base64 chỉ dùng để hiển thị khóa mẫu; RSA không mã hóa chuỗi Base64 dài 44 ký tự.
- Bản mã RSA được hiển thị dưới dạng Base64 và có thể lưu thành tệp `.b64`.

Ngoài ô văn bản UTF-8, phần **Mã hóa mảng byte tùy ý nhập dưới dạng Base64** cho phép thử các byte nhị phân bất kỳ. Ví dụ Base64 `AAECAwQF` biểu diễn 6 byte `00 01 02 03 04 05`. Nhập Base64 nguồn, bấm **Mã hóa mảng byte Base64**, sau đó giải mã bản mã; ứng dụng sẽ giữ đúng mảng nguồn trong phiên để so sánh từng byte.

Với RSA-2048, mô-đun có độ dài 256 byte. RSA-OAEP-SHA256 có giới hạn thông điệp:

`mLen <= k - 2*hLen - 2 = 256 - 2*32 - 2 = 190 byte`.

Do đó, 190 byte là giới hạn của cấu hình RSA-2048 + OAEP-SHA256, không phải giới hạn chung cho mọi kích thước RSA.

### 4.5. Giải mã và so sánh dữ liệu

- Dùng khóa bí mật thuộc cặp khóa tương ứng.
- Dán bản mã Base64 hoặc chọn **Đọc tệp Base64 và giải mã...**.
- Chương trình giải mã thành mảng byte, hiển thị Base64 và thử hiển thị UTF-8 nếu dữ liệu là văn bản hợp lệ.
- Khi dữ liệu nguồn còn trong phiên làm việc, chương trình so sánh từng byte với dữ liệu giải mã.
- Nếu mở ứng dụng mới và giải mã một tệp Base64 cũ, có thể nhập lại văn bản nguồn vào ô dữ liệu nguồn rồi dùng chức năng so sánh.
- Kết quả **GIỐNG HỆT** nghĩa là hai mảng byte có cùng độ dài và mọi byte tương ứng đều bằng nhau.
- Có thể lưu mảng byte đã giải mã thành tệp `.bin` để kiểm tra thêm.

### 4.6. Đo tốc độ RSA

Nhập dữ liệu thử nghiệm (không quá 190 byte với RSA-2048) và chọn số lần lặp. Chương trình đo bốn thao tác:

- Mã hóa bằng khóa công khai.
- Giải mã bằng khóa bí mật.
- Ký RSA-PSS bằng khóa bí mật.
- Xác minh chữ ký bằng khóa công khai.

Kết quả hiển thị tổng thời gian, thời gian trung bình mỗi lần và số lần/giây. Nên thử nhiều lần trong cùng điều kiện, cùng máy, cùng kích thước khóa, cùng dữ liệu và cùng số lần lặp. Không dùng số liệu giả định làm kết quả thực nghiệm.

Số mũ công khai `e` thường là 65537 nên phép toán khóa công khai thường nhanh. Số mũ bí mật `d` thường dài hơn và phép toán khóa bí mật thường mất nhiều thời gian hơn; kết luận cuối cùng phải dựa trên số liệu đo thực tế.

### 4.7. SHA-256 và hiệu ứng avalanche

- Nhập hai nội dung A và B.
- Chuỗi băm SHA-256 được cập nhật tự động khi nội dung thay đổi.
- SHA-256 luôn tạo đầu ra 256 bit = 32 byte = 64 ký tự hex.
- Chương trình đếm số bit khác nhau giữa hai chuỗi băm.

Nếu hai đầu vào chỉ khác một ký tự, hai chuỗi băm thường khác nhau ở nhiều vị trí. Khoảng 128/256 bit khác nhau là xu hướng thống kê, không phải quy tắc bắt buộc cho mọi cặp dữ liệu.

SHA-256 là hàm băm một chiều, không phải thuật toán mã hóa có thể giải mã ngược.

### 4.8. Chữ ký số RSA-PSS

- Nhập dữ liệu cần ký.
- Chọn **Ký bằng khóa bí mật (RSA-PSS)**.
- Ký lần thứ hai với cùng nội dung và cùng khóa bí mật. RSA-PSS sử dụng salt ngẫu nhiên nên chữ ký mới có thể khác chữ ký trước.
- Chọn **Xác minh chữ ký** để kiểm tra chữ ký bằng khóa công khai.
- Thử sửa một ký tự trong dữ liệu rồi xác minh lại; chữ ký cũ phải không hợp lệ với dữ liệu đã sửa.

Ứng dụng dùng API chữ ký chuẩn (`SignData`/`VerifyData`) với RSA-PSS và SHA-256; không tự thực hiện phép “mã hóa hash bằng RSA thô”. PSS dùng salt ngẫu nhiên nên các lần ký cùng dữ liệu/cùng khóa có thể cho chữ ký khác nhau, nhưng mỗi chữ ký vẫn xác minh được.

Hai chữ ký khác nhau không có nghĩa là sai. Điều cần đạt là mỗi chữ ký được xác minh thành công với dữ liệu và khóa công khai tương ứng.

## 5. Các tệp trong dự án

- `Bai2_MaHoaRSA.sln`: tệp solution để Visual Studio mở dự án.
- `Bai2_MaHoaRSA.csproj`: cấu hình WinForms và .NET.
- `Program.cs`: điểm bắt đầu ứng dụng.
- `MainForm.cs`: giao diện và xử lý thao tác người dùng.
- `RsaKeyService.cs`: tạo, xuất, nhập và phân tích khóa/PEM.
- `RsaCryptoService.cs`: các phép toán RSA-OAEP và RSA-PSS.
- `HashService.cs`: tính SHA-256 và đếm số bit khác nhau.
- `TEST_CASES.md`: danh sách tình huống kiểm thử.
- `RUN_WINDOWS.cmd`: tệp chạy nhanh trên Windows bằng .NET SDK.

## 6. Kiểm thử và báo cáo

- Chụp ảnh minh chứng cho từng chức năng sau khi chạy thành công.
- Không để lộ khóa bí mật trong ảnh chụp; nếu cần minh họa tham số khóa bí mật, hãy dùng khóa thử nghiệm và che các giá trị nhạy cảm.
- Ghi lại thời gian thực tế, số lần lặp và kích thước khóa.
- Nếu khóa công khai và khóa bí mật không cùng một cặp, phép giải mã hoặc xác minh sẽ thất bại.
- Môi trường tạo gói mã nguồn không có .NET SDK, do đó chưa thể xác nhận build/chạy trực tiếp tại đây. Hãy biên dịch và kiểm thử trên máy Windows trước khi nộp.


## 7. Tài liệu tham khảo

- RFC 7468 — Textual Encodings of PKIX, PKCS, and CMS Structures: https://www.rfc-editor.org/rfc/rfc7468.html
- RFC 8017 — PKCS #1: RSA Cryptography Specifications: https://www.rfc-editor.org/rfc/rfc8017.html
- Microsoft Learn — `RSA.ImportFromPem`: https://learn.microsoft.com/en-us/dotnet/api/system.security.cryptography.rsa.importfrompem
- Microsoft Learn — `RSASignaturePadding.Pss`: https://learn.microsoft.com/en-us/dotnet/api/system.security.cryptography.rsasignaturepadding.pss
