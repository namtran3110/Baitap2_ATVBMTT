# MÔN HỌC: AN TOÀN VÀ BẢO MẬT THÔNG TIN
## HỌ VÀ TÊN: TRẦN NHẤT NAM
## MSSV: K235480106001
## LỚP: K59KMT

---

# BÀI 2: MÃ HÓA BẤT ĐỐI XỨNG RSA, SHA-256 VÀ CHỮ KÝ SỐ

## 1. Mục tiêu bài tập

Xây dựng ứng dụng desktop bằng C# Windows Forms để tìm hiểu và thực hành thuật toán mã hóa bất đối xứng RSA. Bên cạnh chức năng mã hóa và giải mã, chương trình còn hỗ trợ phân tích khóa PEM, tính giá trị băm SHA-256 và tạo chữ ký số.

Các chức năng chính:

  * Sinh cặp khóa RSA với các kích thước 2048, 3072 hoặc 4096 bit.
  * Xuất khóa công khai và khóa bí mật ra các tệp PEM riêng biệt; nhập lại khóa từ tệp PEM.
  * Xem nội dung PEM, phân tích dữ liệu DER/ASN.1 và tìm hiểu ý nghĩa các trường `n`, `e`, `d`, `p`, `q`, `dp`, `dq`, `inverseQ`.
  * Mã hóa dữ liệu dạng mảng byte bằng khóa công khai, chuyển bản mã sang Base64 và lưu ra tệp.
  * Giải mã bản mã Base64 bằng khóa bí mật; so sánh dữ liệu sau giải mã với dữ liệu nguồn theo từng byte.
  * Đo thời gian mã hóa, giải mã, ký và xác minh chữ ký để đối chiếu hiệu năng của các thao tác RSA.
  * Tự động tính SHA-256 khi thay đổi dữ liệu đầu vào và đếm số bit khác nhau giữa hai giá trị băm.
  * Tạo chữ ký số RSA-PSS với SHA-256; ký lại cùng dữ liệu bằng cùng khóa để quan sát việc chữ ký có thể khác nhau qua các lần ký.

--> Qua bài tập, cần hiểu sự khác nhau giữa khóa công khai và khóa bí mật, cách lưu trữ khóa bằng PEM, giới hạn dữ liệu khi mã hóa trực tiếp bằng RSA, nguyên lý hàm băm SHA-256 và cơ chế ký/xác minh chữ ký số.

## 2. Công nghệ sử dụng

  * Ngôn ngữ lập trình: C#.
  * Loại ứng dụng: Windows Forms, chạy trên Windows; không phải ứng dụng web.
  * Nền tảng: .NET 8
  * Thư viện mật mã: `System.Security.Cryptography`.
  * Mã hóa RSA: RSA-OAEP với SHA-256.
  * Hàm băm: SHA-256, đầu ra 256 bit = 32 byte = 64 ký tự hexadecimal.
  * Chữ ký số: RSA-PSS kết hợp SHA-256 (`RSASignaturePadding.Pss`).
  * Đo thời gian: `Stopwatch`.
  * Định dạng khóa: PEM; phần thân Base64 được giải mã thành cấu trúc DER theo quy tắc ASN.1.

### 2.1. Nguyên lý hoạt động của RSA

RSA là thuật toán mã hóa bất đối xứng, sử dụng một cặp khóa có quan hệ toán học với nhau:

  * **Khóa công khai (Public Key):** gồm các thành phần chính `n` và `e`. Khóa này có thể chia sẻ cho người khác, được dùng trong chương trình để mã hóa dữ liệu và xác minh chữ ký số.
  * **Khóa bí mật (Private Key):** cũng chứa `n`, `e`, đồng thời có các tham số bí mật như `d`, `p`, `q`, `dp`, `dq` và `inverseQ`. Khóa này dùng để giải mã dữ liệu và tạo chữ ký số, vì vậy phải được bảo vệ.

Trong đó:

  * `n` (Modulus): mô-đun RSA, bằng tích của hai số nguyên tố bí mật `p` và `q`.
  * `e` (Public Exponent): số mũ công khai. Giá trị thường gặp là `65537`.
  * `d` (Private Exponent): số mũ bí mật, có quan hệ toán học với `e`.
  * `p`, `q`: hai số nguyên tố bí mật được dùng để tạo mô-đun `n`.
  * `dp`, `dq`, `inverseQ`: các tham số hỗ trợ tối ưu phép toán sử dụng khóa bí mật.

--> Khi mã hóa, người gửi dùng khóa công khai của người nhận; người nhận dùng khóa bí mật tương ứng để giải mã. Với chữ ký số, chiều sử dụng khóa khác: người ký tạo chữ ký bằng khóa bí mật, người nhận xác minh bằng khóa công khai.

### 2.2. Vì sao dữ liệu RSA bị giới hạn 190 byte?

Ứng dụng sử dụng RSA-2048 cùng OAEP-SHA256 theo yêu cầu bài tập. Với RSA-2048, kích thước mô-đun là 2048 bit = 256 byte. OAEP-SHA256 dành 32 byte cho giá trị băm và có công thức giới hạn thông điệp:

`mLen <= k - 2*hLen - 2`

Trong đó `k = 256 byte`, `hLen = 32 byte`, do đó:

`mLen <= 256 - 2*32 - 2 = 190 byte`

--> Vì vậy, với RSA-2048 + OAEP-SHA256, dữ liệu đầu vào tối đa trong một lần mã hóa là 190 byte. Chương trình cũng áp dụng mức trần 190 byte theo yêu cầu bài tập ngay cả khi nạp khóa RSA lớn hơn. Khi thử nghiệm văn bản tiếng Việt, cần chú ý chương trình đếm **byte UTF-8**, không phải số ký tự hiển thị.

Trong ứng dụng thực tế, RSA thường dùng để bảo vệ khóa AES; AES đảm nhiệm việc mã hóa dữ liệu lớn. Bài tập này mã hóa trực tiếp một mảng byte nhỏ để quan sát hoạt động của RSA.

## 3. Cấu trúc cây thư mục dự án

Dự án được tổ chức thành các tệp chính như sau:

```text
Bai2_MaHoaRSA/
├── Bai2_MaHoaRSA.sln       # Solution để mở dự án bằng Visual Studio
├── Bai2_MaHoaRSA.csproj    # Cấu hình WinForms và .NET 8
├── Program.cs              # Điểm bắt đầu chương trình
├── MainForm.cs             # Giao diện và xử lý thao tác người dùng
├── RsaKeyService.cs        # Sinh, xuất, nhập và phân tích khóa RSA/PEM
├── RsaCryptoService.cs     # Mã hóa, giải mã, ký và xác minh RSA
├── HashService.cs          # Tính SHA-256 và đếm số bit khác nhau
├── DerStructureInspector.cs # Phân tích cấu trúc DER/ASN.1 theo byte
├── README.md               # Tài liệu giới thiệu dự án
├── HUONG_DAN_SU_DUNG.md    # Hướng dẫn chạy và sử dụng
├── TEST_CASES.md           # Danh sách trường hợp kiểm thử
└── RUN_WINDOWS.cmd         # Tệp khởi chạy nhanh trên Windows
```

> **<img width="1920" height="1080" alt="image" src="https://github.com/user-attachments/assets/92bf4e40-fcc0-4a03-b424-2f2898c31aee" />**  
- Cấu trúc dự án trong Visual Studio
`images/01-cau-truc-du-an.png`

* * *

## 4. Quá trình thực hiện

### 4.1. Mở và chạy ứng dụng

  * Mở `Bai2_MaHoaRSA.sln` bằng Visual Studio.
  * Đảm bảo máy đã cài workload **.NET desktop development** và SDK phù hợp với cấu hình dự án.
  * Chọn cấu hình `Debug`, sau đó nhấn `F5` để chạy ứng dụng.
  * Có thể chạy tệp `RUN_WINDOWS.cmd` nếu đã cài .NET SDK.

Ứng dụng có bốn khu vực chức năng chính: **Khóa và PEM**, **Mã hóa và giải mã**, **SHA-256**, **Chữ ký số và tốc độ**.

> **<img width="1920" height="1080" alt="image" src="https://github.com/user-attachments/assets/931f6ffd-7d6f-48db-ac48-645d0be1c342" />
Giao diện chính của ứng dụng RSA**  
`images/02-giao-dien-chinh.png`

### 4.2. Sinh cặp khóa RSA và xuất PEM

  * Chuyển sang tab **Khóa và PEM**.
  * Chọn kích thước khóa trong danh sách: `2048 bit`, `3072 bit` hoặc `4096 bit`.
  * Nhấn **Sinh cặp khóa** để tạo khóa công khai và khóa bí mật.
  * Nhấn **Xuất PEM khóa công khai** để lưu khóa công khai, ví dụ `khoa_cong_khai.pem`.
  * Nhấn **Xuất PEM khóa bí mật** để lưu khóa bí mật, ví dụ `khoa_bi_mat.pem`.

Khóa công khai được xuất theo cấu trúc SubjectPublicKeyInfo (SPKI), thường có phần đầu `-----BEGIN PUBLIC KEY-----`. Khóa bí mật được xuất theo PKCS#8, thường có phần đầu `-----BEGIN PRIVATE KEY-----`.

--> Việc lưu khóa thành hai tệp riêng giúp thử nghiệm quy trình tạo khóa, phân phối khóa công khai và giữ kín khóa bí mật. Hai khóa phải thuộc cùng một cặp thì mới giải mã hoặc xác minh chữ ký như mong muốn.

**<img width="1920" height="1080" alt="image" src="https://github.com/user-attachments/assets/5bfb3eec-2435-40a4-bd3d-f818da5d1c27" />
<img width="1920" height="1080" alt="image" src="https://github.com/user-attachments/assets/ed19b2ff-8435-4e1d-ba1b-75d402ac1470" />
<img width="1920" height="1080" alt="image" src="https://github.com/user-attachments/assets/263ef36e-091d-4d80-a5ae-c6ad8a4c671a" />** 
- Sinh và xuất cặp khóa RSA 

### 4.3. Nhập khóa và kiểm tra cặp khóa

  * Nhấn **Nhập khóa công khai...** và chọn tệp PEM khóa công khai đã xuất.
  * Nhấn **Nhập khóa bí mật...** và chọn tệp PEM khóa bí mật đã xuất.
  * Quan sát trạng thái khóa hiển thị trên giao diện.
  * Khi cả hai khóa được nạp, chương trình sử dụng một dữ liệu thử ngẫu nhiên để kiểm tra khả năng mã hóa bằng khóa công khai và giải mã bằng khóa bí mật. Nếu dữ liệu khôi phục trùng với dữ liệu thử, chương trình báo hai khóa khớp.

Có thể thử nhập khóa công khai của cặp A và khóa bí mật của cặp B để quan sát trạng thái không khớp. Không dùng cặp khóa khác nhau để thử mã hóa rồi kỳ vọng giải mã thành công.

**<img width="1920" height="1080" alt="image" src="https://github.com/user-attachments/assets/4693390d-fbbe-4324-b921-0a3d37f7b162" />
<img width="1920" height="1080" alt="image" src="https://github.com/user-attachments/assets/79ebb1c6-024f-4678-a9a9-d13a73e26013" />**  
- Nhập PEM và kiểm tra cặp khóa

### 4.4. Xem nội dung PEM và ý nghĩa các byte

PEM là cách biểu diễn dữ liệu mật mã dưới dạng văn bản. Một tệp PEM thường có ba phần:

  1. Dòng mở đầu cho biết loại dữ liệu, ví dụ `-----BEGIN PUBLIC KEY-----`.
  2. Phần thân Base64 chứa dữ liệu nhị phân DER được biểu diễn thành ký tự.
  3. Dòng kết thúc, ví dụ `-----END PUBLIC KEY-----`.

Base64 **không phải thuật toán mã hóa** và không tự bảo vệ bí mật của khóa. Khi giải mã phần thân Base64, ta thu được dữ liệu DER theo cấu trúc ASN.1. DER sử dụng các trường kiểu **Tag – Length – Value (TLV)**, nên vị trí và số byte của từng trường phụ thuộc vào loại khóa và kích thước dữ liệu.

Các loại PEM chính mà chương trình hỗ trợ:

| Nhãn PEM | Cấu trúc | Thành phần chính |
|---|---|---|
| `PUBLIC KEY` | SubjectPublicKeyInfo (SPKI) | Thông tin thuật toán và BIT STRING chứa cấu trúc khóa công khai RSA gồm `n`, `e`. |
| `RSA PUBLIC KEY` | PKCS#1 `RSAPublicKey` | Hai số nguyên `n` và `e`. |
| `PRIVATE KEY` | PKCS#8 `PrivateKeyInfo` | Thông tin phiên bản, thuật toán và OCTET STRING chứa tham số khóa riêng RSA. |
| `RSA PRIVATE KEY` | PKCS#1 `RSAPrivateKey` | `n`, `e`, `d`, `p`, `q`, `dp`, `dq`, `inverseQ` và các trường liên quan. |

Một số mã Tag ASN.1 thường gặp:

| Byte Tag (hex) | Kiểu ASN.1 | Ý nghĩa thường gặp trong cấu trúc khóa |
|---|---|---|
| `30` | `SEQUENCE` | Nhóm các trường thành một cấu trúc. |
| `02` | `INTEGER` | Số nguyên, ví dụ `n`, `e`, `d`, `p`, `q`. |
| `03` | `BIT STRING` | Trường chứa chuỗi bit; trong SPKI có thể bao bọc cấu trúc khóa công khai RSA. |
| `04` | `OCTET STRING` | Chuỗi byte; trong PKCS#8 chứa dữ liệu khóa bí mật DER. |
| `06` | `OBJECT IDENTIFIER` | Định danh thuật toán, ví dụ thuật toán RSA. |
| `05` | `NULL` | Trường tham số NULL trong một số cấu trúc. |

Các byte trên là mã Tag thường gặp, **không có nghĩa mọi tệp PEM đều bắt đầu bằng cùng một dãy byte**. Sau Tag còn có phần Length và Value; độ dài có thể được mã hóa bằng một hoặc nhiều byte. Ứng dụng phân tích nhãn PEM, độ dài DER, một phần dữ liệu DER dạng HEX, cây TLV kèm vị trí byte và các tham số RSA mà thư viện đọc được.

Các bước thực hiện:

  * Trong tab **Khóa và PEM**, bấm **Nạp PEM từ tệp...** hoặc dán nội dung PEM vào ô bên trái.
  * Nhấn **Phân tích PEM**.
  * Quan sát nhãn PEM, độ dài DER, cây cấu trúc theo vị trí byte và các tham số RSA ở vùng kết quả.
  * Với khóa công khai, chú ý `n` và `e`. Với khóa bí mật, chú ý các tên trường `n`, `e`, `d`, `p`, `q`, `dp`, `dq`, `inverseQ`.

**<img width="1920" height="1080" alt="image" src="https://github.com/user-attachments/assets/1f5c90f2-7331-4ec0-bbdd-a2367c183924" />**  
- Phân tích PEM khóa công khai

**<img width="1920" height="1080" alt="image" src="https://github.com/user-attachments/assets/2708a4a9-3469-4f33-be76-f2e7ba6ef7b2" />**  
- Phân tích cấu trúc PEM khóa bí mật

### 4.5. Mã hóa dữ liệu và lưu bản mã Base64

Chương trình hỗ trợ ba cách tạo dữ liệu đầu vào:

  * **Văn bản UTF-8:** nhập nội dung vào ô văn bản. Chương trình chuyển văn bản thành mảng byte UTF-8, kiểm tra giới hạn byte rồi mã hóa bằng khóa công khai.
  * **Khóa AES-256 mẫu:** nhấn **Tạo khóa AES-256 mẫu (32 byte)** để sinh một mảng 32 byte ngẫu nhiên, đúng độ dài khóa AES-256. Sau đó nhấn **Mã hóa khóa AES mẫu** để mã hóa mảng byte đó bằng RSA.
  * **Mảng byte tùy ý nhập dạng Base64:** dán Base64 của dữ liệu nhị phân vào ô tương ứng. Chương trình giải mã Base64 về mảng byte thật, hiển thị số byte rồi thực hiện mã hóa RSA.

Ví dụ, chuỗi Base64 `AAECAwQF` biểu diễn mảng 6 byte:

`00 01 02 03 04 05`

Điều cần phân biệt là chương trình mã hóa **32 byte nhị phân** của khóa AES mẫu, không mã hóa chuỗi Base64 hiển thị của khóa đó. Base64 chỉ là cách biểu diễn dữ liệu nhị phân thành văn bản để dễ lưu và truyền.

Quy trình mã hóa:

  * Chọn tab **Mã hóa và giải mã**.
  * Nhập văn bản ngắn hoặc nhập mảng byte bằng Base64.
  * Kiểm tra số byte đầu vào và bảo đảm dữ liệu không quá giới hạn.
  * Nhấn nút mã hóa tương ứng. Bản mã được hiển thị dưới dạng Base64.
  * Nhấn **Lưu bản mã ra tệp...** và lưu kết quả, ví dụ `ban_ma_rsa.b64`.

Với RSA-2048, bản mã có độ dài 256 byte do kích thước mô-đun RSA là 2048 bit. Khi mã hóa cùng dữ liệu bằng OAEP, kết quả có thể thay đổi qua các lần chạy vì OAEP sử dụng tính ngẫu nhiên; việc bản mã khác nhau không có nghĩa là mã hóa sai.

<img width="1920" height="1080" alt="image" src="https://github.com/user-attachments/assets/c095a905-b0b9-4c87-8eee-887d8e9987b2" />
- Mã hóa RSA và bản mã Base64

<img width="1920" height="1080" alt="image" src="https://github.com/user-attachments/assets/aa8c804a-c39f-4d16-a137-cf7ad7fed348" />  
- Lưu bản mã Base64 ra tệp

### 4.6. Giải mã và so sánh dữ liệu nguồn

  * Dùng khóa bí mật đúng cặp với khóa công khai đã mã hóa dữ liệu.
  * Có thể nhấn **Giải mã bản mã hiện tại** hoặc **Đọc tệp Base64 và giải mã...** để đọc bản mã đã lưu.
  * Chương trình giải mã Base64 thành mảng byte, sau đó thực hiện RSA-OAEP-SHA256 để khôi phục dữ liệu.
  * Kết quả được hiển thị ở dạng Base64; nếu dữ liệu là văn bản UTF-8 hợp lệ, chương trình hiển thị thêm nội dung văn bản.
  * Nhấn **So sánh với dữ liệu nguồn** để so sánh từng byte giữa dữ liệu ban đầu và dữ liệu đã giải mã.

--> Chỉ khi hai mảng byte có cùng độ dài và toàn bộ byte ở từng vị trí đều trùng khớp thì dữ liệu mới được xác nhận là **GIỐNG HỆT**. So sánh tên tệp hoặc kích thước tệp đơn thuần chưa đủ chứng minh nội dung trùng nhau.

Nếu đóng ứng dụng rồi mở lại để giải mã một tệp cũ, dữ liệu nguồn của phiên trước không còn trong bộ nhớ. Khi đó, cần nhập lại dữ liệu nguồn hoặc Base64 nguồn để đối chiếu. Nếu dùng khóa bí mật không tương ứng, thao tác giải mã phải thất bại.

<img width="1920" height="1080" alt="image" src="https://github.com/user-attachments/assets/6fb75e17-8c8c-444a-ac84-f8bb3895d4f6" />  
- Giải mã và so sánh dữ liệu theo byte

### 4.7. Kiểm tra giới hạn 190 byte

Với khóa RSA-2048 và OAEP-SHA256, chương trình giới hạn mảng byte đầu vào ở mức 190 byte. Có thể kiểm tra bằng văn bản chỉ gồm ký tự ASCII `A`, vì mỗi ký tự ASCII này chiếm một byte trong UTF-8:

  * Thử dữ liệu dài đúng 190 ký tự `A`. Bộ đếm phải báo 190 byte và thao tác mã hóa có thể thực hiện.
  * Thêm một ký tự `A` để dữ liệu thành 191 byte. Chương trình phải báo vượt giới hạn và không thực hiện mã hóa.
  * Có thể thực hiện phép thử tương tự bằng ô mảng byte Base64 với dữ liệu có chiều dài tương ứng.

Với dữ liệu tiếng Việt, số byte UTF-8 thường lớn hơn số ký tự do một số ký tự cần nhiều byte để biểu diễn. Vì thế, phải căn cứ vào bộ đếm byte của chương trình, không chỉ đếm số ký tự.

<img width="1920" height="1080" alt="image" src="https://github.com/user-attachments/assets/e79b4aab-c44d-450e-92d3-5056a5b89cb9" />
<img width="1920" height="1080" alt="image" src="https://github.com/user-attachments/assets/90160120-c6ca-4696-b3f5-82ed96d34690" />
<img width="1920" height="1080" alt="image" src="https://github.com/user-attachments/assets/7280d890-30a6-4377-bf3b-a17042daa771" />
- Dữ liệu 190 byte được chương trình chấp nhận và mã hóa thành công, dữ liệu 191 byte bị từ chối mã hóa.

### 4.8. Tính giá trị băm SHA-256 và hiệu ứng avalanche

SHA-256 là hàm băm mật mã, nhận dữ liệu đầu vào có độ dài bất kỳ và tạo ra giá trị băm cố định dài 256 bit. Trong chương trình, kết quả được hiển thị theo dạng hexadecimal nên có 64 ký tự hex.

  * Chọn tab **SHA-256**.
  * Nhập dữ liệu A và B. Mặc định hai chuỗi là `An toàn thông tin` và `An toàn thông tin!`, chỉ khác nhau một ký tự.
  * Quan sát hai giá trị băm. Khi thay đổi dữ liệu A hoặc B, chương trình tự động tính lại SHA-256.
  * Quan sát số bit khác nhau giữa hai giá trị băm, được biểu diễn theo dạng `x/256`.

--> Hiệu ứng avalanche có nghĩa là một thay đổi nhỏ của dữ liệu đầu vào thường làm nhiều bit của đầu ra thay đổi. Với hai chuỗi băm SHA-256 của các đầu vào khác nhau, số bit khác nhau có kỳ vọng thống kê xấp xỉ 128 trên tổng số 256 bit. Đây là xu hướng thống kê, không phải yêu cầu mọi lần phải đúng 128 bit.

SHA-256 là hàm băm một chiều, không phải thuật toán mã hóa. Không thể dùng khóa để giải mã ngược giá trị băm như với bản mã RSA.

<img width="1920" height="1076" alt="image" src="https://github.com/user-attachments/assets/a1b489b7-de68-4afc-b743-1c998e8663c4" />
- So sánh SHA-256 và hiệu ứng avalanche

### 4.9. Tạo và xác minh chữ ký số RSA-PSS

Chữ ký số dùng để kiểm tra tính toàn vẹn của dữ liệu và xác thực chữ ký được tạo từ khóa bí mật tương ứng. Trong ứng dụng, chữ ký được tạo bằng **RSA-PSS + SHA-256**.

Cần phân biệt rằng không nên tự cài đặt chữ ký số bằng cách “mã hóa trực tiếp chuỗi băm bằng RSA thô”. Chương trình sử dụng API chữ ký số chuẩn `SignData` và `VerifyData`, kết hợp SHA-256 với RSA-PSS.

Quy trình thực hiện:

  * Chọn tab **Chữ ký số và tốc độ**.
  * Nhập dữ liệu cần ký vào ô **Dữ liệu cần ký (UTF-8)**.
  * Nhấn **Ký bằng khóa bí mật (RSA-PSS)**. Chương trình băm dữ liệu bằng SHA-256 trong quá trình ký và hiển thị chữ ký ở dạng Base64.
  * Nhấn **Xác minh chữ ký** để dùng khóa công khai tương ứng kiểm tra chữ ký.
  * Giữ nguyên dữ liệu và khóa, nhấn **Ký bằng khóa bí mật (RSA-PSS)** lần nữa. RSA-PSS sử dụng salt ngẫu nhiên, vì vậy chữ ký của cùng một dữ liệu với cùng khóa có thể khác chữ ký ở lần ký trước.
  * Kiểm tra trạng thái thông báo sau lần ký thứ hai. Nếu chữ ký khác nhau, chương trình hiển thị thông báo nhận biết tình huống này.
  * Thử sửa một ký tự trong dữ liệu nhưng giữ chữ ký cũ, sau đó nhấn **Xác minh chữ ký**. Chữ ký cũ phải không hợp lệ với dữ liệu đã bị thay đổi.

Điểm quan trọng của yêu cầu bài tập là chữ ký có thể khác nhau qua các lần ký, nhưng việc xác minh vẫn thành công khi sử dụng đúng dữ liệu ký và khóa công khai tương ứng. Chữ ký khác nhau không có nghĩa dữ liệu bị thay đổi hoặc chữ ký bị lỗi.

<img width="1920" height="1080" alt="image" src="https://github.com/user-attachments/assets/376ac5e7-590c-427c-9444-cf34c730fac2" />
  
> **Cách chụp:** Nhập một nội dung cố định, ký lần đầu. Có thể lưu chữ ký đầu tiên ra tệp bằng nút **Lưu chữ ký ra tệp...**. Giữ nguyên nội dung và khóa, nhấn ký lần thứ hai. Chụp trạng thái thông báo cho biết chữ ký mới khác chữ ký trước.
- Nội dung: Mười điểm môn thầy Cốp
- Chữ kí lần đầu:
  ```d+hzEow6lOtAfsLbEArtKBtHgwZ9Pli9/M7H9XVwtPD2ZyA3jnFmBGjTq1u9fO1VJsX2OLk2s4GQMBmSc5JZMA1b7Ks+Z8Lq6gYlmigPMYexg6ApmcuKxnr936A9tx7/dxFPGbICVQ4Vsgjqt+E3o+Ks+WvcWOs13n+puYKMKNgf3UEH2p9H6v6jRMhk2ntAL3/kOgxHE+xyeoi+g7FZXw5kDFt7fOihCDE7v3Lt+CZTqf3+3jXfZkbcpBdORyVSLrtgjNbx6mxGw7BoF8cZLLsO9X7bXia/b1tHK6iGTEGjzcw5A1fjtWSMXtV90hVK9N8pdlxxhq6Dhsu2YsV1aw==```
  
- Chữ kí lần 2:
 ```lzMwYYxp02Fm5bvEPZ3oiXB/t/z/uJ/SO9VRClo7ZGHqrtMSxKJujGzYBUnf5a5cioVYUQNo1zOxUPWtFnDubmgIeJ5sExi75mu7xGcMGfPNBLpD29sb18OqsdJcr3y5hFT8MTzTTNPjZWB5VWlaK9TzZ1wBP8xtw+IZrQFpDmrW5v5CyNTjBARSI/YZqBvKqE3/9j4f6L6Negp+zgrSeo/YhyX0Yppbax0i++sRK5n5yGljqEhV+u0lsfx3AhxP10KUpTQi4et33Ye6I2sD7byH+/Te3KHgTWszkFkZ9xmQGAIZY8pbtNJz0+UGFRxZhx6MgZEoo3oj6T8N4t4raw==```

<img width="1920" height="1080" alt="image" src="https://github.com/user-attachments/assets/da608421-9fd3-4caf-b0d0-544a521a4784" />
<img width="1918" height="1080" alt="image" src="https://github.com/user-attachments/assets/7b983895-4aa9-4755-9aee-be96cedd2b16" />
- Chữ kí hợp lệ và không hợp lệ sau khi thay đổi 1 chút trong dữ liệu.

### 4.10. Đo tốc độ mã hóa, giải mã, ký và xác minh RSA

Chương trình có chức năng đo thời gian của bốn thao tác:

  1. Mã hóa bằng khóa công khai.
  2. Giải mã bằng khóa bí mật.
  3. Ký RSA-PSS bằng khóa bí mật.
  4. Xác minh chữ ký bằng khóa công khai.

Cách thực hiện:

  * Bảo đảm cả khóa công khai và khóa bí mật đã được nạp và thuộc cùng một cặp.
  * Nhập một dữ liệu thử nghiệm không vượt quá giới hạn byte.
  * Chọn số lần lặp, ví dụ 100 lần. Sau khi chạy thử thành công có thể tăng lên 1.000 lần để giảm ảnh hưởng của dao động thời gian.
  * Nhấn **Chạy đo tốc độ**.
  * Ghi lại tổng thời gian, thời gian trung bình mỗi lần và số thao tác mỗi giây cho từng phép toán.
  * Lặp lại với RSA-3072 và RSA-4096 nếu cần so sánh ảnh hưởng của kích thước khóa.

Chương trình làm nóng các đường thực thi trước khi đo để giảm ảnh hưởng khởi tạo/JIT. Số lượt làm nóng không được tính vào thời gian đo. Dù vậy, kết quả vẫn phụ thuộc CPU, thư viện mật mã, hệ điều hành và các tác vụ đang chạy trên máy.

Số mũ công khai `e` thường là `65537`, có giá trị nhỏ so với số mũ bí mật `d`. Vì vậy, phép toán dùng khóa công khai thường nhanh hơn phép toán dùng khóa bí mật. Khóa riêng còn có các tham số hỗ trợ tối ưu như `dp`, `dq`, `inverseQ`, nên thời gian đo thực tế vẫn phải được lấy từ ứng dụng, không nên kết luận bằng suy đoán đơn thuần.

<img width="1920" height="1080" alt="image" src="https://github.com/user-attachments/assets/e4c13b28-9795-4055-9380-48f08de05a8a" />
- Kết quả đo tốc độ RSA

## 5. Các tệp chính trong mã nguồn

  * `Bai2_MaHoaRSA.sln`: mở solution bằng Visual Studio.
  * `Bai2_MaHoaRSA.csproj`: khai báo cấu hình dự án WinForms và nền tảng .NET.
  * `Program.cs`: khởi động ứng dụng và mở cửa sổ `MainForm`.
  * `MainForm.cs`: thiết kế giao diện, nhận thao tác người dùng, gọi các hàm xử lý và hiển thị kết quả.
  * `RsaKeyService.cs`: tạo cặp khóa, xuất/nhập PEM, đọc tham số RSA và mô tả cấu trúc PEM.
  * `RsaCryptoService.cs`: thực hiện RSA-OAEP-SHA256, RSA-PSS-SHA256 và kiểm tra giới hạn dữ liệu.
  * `HashService.cs`: tính SHA-256 và đếm số bit khác nhau giữa hai giá trị băm.
  * `DerStructureInspector.cs`: phân tích cấu trúc DER/ASN.1 theo vị trí byte và trường TLV.
  * `HUONG_DAN_SU_DUNG.md`: hướng dẫn chạy và sử dụng ứng dụng.
  * `TEST_CASES.md`: danh sách các trường hợp kiểm thử chức năng.
  * `RUN_WINDOWS.cmd`: chạy ứng dụng từ Windows khi đã cài SDK tương thích.

## 6. Bảng kiểm thử chức năng

Các trường hợp dưới đây cần được thực hiện trực tiếp trên máy Windows. Chỉ đổi trạng thái sang **Đạt** khi đã chạy thử và quan sát được kết quả mong đợi.

| STT | Chức năng | Cách kiểm thử | Kết quả mong đợi | Kết quả thực tế |
|---:|---|---|---|---|
| 1 | Sinh cặp khóa | Sinh khóa RSA-2048 | Tạo được khóa công khai và khóa bí mật | Đạt |
| 2 | Xuất PEM | Xuất cả khóa công khai và khóa bí mật | Có hai tệp PEM đúng nhãn | Đạt |
| 3 | Nhập PEM | Nạp lại hai tệp vừa xuất | Ứng dụng đọc được hai khóa | Đạt |
| 4 | Kiểm tra cặp khóa | Nạp public/private cùng cặp | Trạng thái báo hai khóa khớp | Đạt |
| 5 | Phân tích PEM công khai | Nạp PEM công khai và phân tích | Hiện `n`, `e`, độ dài DER và cây TLV | Đạt |
| 6 | Phân tích PEM bí mật | Nạp PEM bí mật và phân tích | Hiện tên `n`, `e`, `d`, `p`, `q`, `dp`, `dq`, `inverseQ` | Đạt |
| 7 | Kiểm tra PEM sai | Sửa Base64 hoặc xóa dòng END | Ứng dụng báo dữ liệu không hợp lệ | Đạt |
| 8 | Mã hóa văn bản | Mã hóa văn bản ngắn | Tạo bản mã RSA dạng Base64 | Đạt |
| 9 | Mã hóa khóa AES-256 mẫu | Sinh khóa AES mẫu và mã hóa | Mã hóa mảng 32 byte thành công | Đạt |
| 10 | Mã hóa mảng byte Base64 | Nhập `AAECAwQF`, mã hóa và giải mã | Thu được đúng 6 byte ban đầu | Đạt |
| 11 | Giới hạn 190 byte | Thử dữ liệu 190 byte | Bộ đếm báo 190 byte và mã hóa được | Đạt |
| 12 | Vượt giới hạn | Thử dữ liệu 191 byte với RSA-2048 | Ứng dụng từ chối mã hóa | Đạt |
| 13 | Lưu bản mã | Lưu bản mã ra `.b64` | Tệp chứa Base64 hợp lệ | Đạt |
| 14 | Giải mã và so sánh | Giải mã bằng private key đúng | Dữ liệu khôi phục giống hệt nguồn theo byte | Đạt |
| 15 | Giải mã sai khóa | Dùng private key không cùng cặp | Giải mã thất bại | Đạt |
| 16 | Tính SHA-256 | Thay đổi một ký tự đầu vào | Giá trị băm tự cập nhật | Đạt |
| 17 | Hiệu ứng avalanche | So sánh hai đầu vào gần giống nhau | Hiển thị số bit khác nhau trên 256 bit | Đạt |
| 18 | Ký số RSA-PSS | Ký dữ liệu bằng private key | Tạo chữ ký Base64 | Đạt |
| 19 | Ký lại cùng dữ liệu | Ký lần nữa không đổi dữ liệu/khóa | Chữ ký thường khác và trạng thái ghi nhận sự khác nhau | Chưa thử |
| 20 | Xác minh chữ ký hợp lệ | Xác minh bằng public key cùng cặp | Báo chữ ký hợp lệ | Chưa thử |
| 21 | Sửa dữ liệu sau khi ký | Đổi một ký tự, giữ chữ ký cũ | Báo chữ ký không hợp lệ | Chưa thử |
| 22 | Đo tốc độ RSA | Chạy 100 lần | Hiển thị kết quả cho bốn thao tác | Chưa thử |

## 7. Bảng số liệu thực nghiệm

### 7.1. So sánh tốc độ theo kích thước khóa

Chạy thử trên cùng một máy, dùng cùng dữ liệu và số lần lặp. Nên chạy ít nhất ba lượt cho mỗi kích thước khóa rồi ghi lại kết quả. Điền số liệu từ ứng dụng; không dùng số minh họa hoặc tự ước lượng.

| Kích thước khóa | Số lần lặp | Mã hóa công khai (ms/lần) | Giải mã bí mật (ms/lần) | Ký RSA-PSS (ms/lần) | Xác minh (ms/lần) |
|---|---:|---:|---:|---:|---:|
| RSA-2048 | 100 | [0.0551] | [1.6602] | [1.6600] | [0.0599] |
| RSA-3072 | 100 | [0.1076] | [5.1141] | [5.1612] | [0.1071] |
| RSA-4096 | 100 | [0.1833] | [11.6504] | [11.5609] | [0.1824] |

Công thức tham khảo:

```text
Thời gian trung bình (ms/lần) = Tổng thời gian (ms) / Số lần lặp
Tốc độ (lần/giây) = Số lần lặp / Tổng thời gian (giây)
```

### 7.2. Nhận xét sau khi có số liệu

Sau khi chạy thử, điền nhận xét dựa trên kết quả đã đo:

  * Phép toán nhanh nhất trong lần thử: **Mã hóa công khai**.
  * Phép toán chậm nhất trong lần thử: **Giải mã bí mật**.
  * Khi tăng kích thước khóa từ RSA-2048 lên RSA-3072/RSA-4096, thời gian thay đổi như thế nào: **Thời gian của từng thao tác đều tăng lên, từ mili giây cho đến vài giây tùy vào loại thao tác**.
  * So sánh thời gian mã hóa bằng khóa công khai và giải mã bằng khóa bí mật: **Thời gian mã hóa có tốc độ vượt trội hơn giải mã. Nhanh hơn từ 32-65 lần**.

--> Kết quả có thể khác nhau giữa các máy, tùy thuộc vào cấu hình thử nghiệm chương trình.

## 8. Nhận xét và kết luận

### 8.1. Nhận xét về chức năng

Sau khi hoàn tất kiểm thử, Em nhận thấy chương trình đã hoạt động tương đối ổn, các chức năng: sinh/xuất/nhập khóa PEM, phân tích cấu trúc DER/ASN.1, mã hóa và giải mã mảng byte, so sánh dữ liệu theo byte, tính SHA-256, tạo/xác minh chữ ký RSA-PSS và đo tốc độ đều hoạt động hoàn toàn bình thường.

### 8.2. Nhận xét về RSA và PEM

Qua phần phân tích PEM, có thể thấy PEM chủ yếu là cách biểu diễn dữ liệu khóa dưới dạng văn bản; dữ liệu Base64 bên trong được giải mã thành DER/ASN.1. Các tham số của khóa RSA nằm trong cấu trúc nhị phân, không phải các dòng `n`, `e`, `d` được viết trực tiếp trong tệp PEM.

Khóa công khai gồm `n` và `e`; khóa bí mật còn chứa các tham số nhạy cảm như `d`, `p`, `q`, `dp`, `dq` và `inverseQ`. Tệp khóa bí mật cần được quản lý cẩn thận. Phiên bản ứng dụng này xuất khóa riêng PEM không dùng mật khẩu để mã hóa tệp, do đó chỉ nên dùng khóa thử nghiệm và không công khai tệp private PEM.

### 8.3. Nhận xét về SHA-256 và chữ ký số

SHA-256 luôn tạo ra đầu ra dài 256 bit. Khi thay đổi rất nhỏ dữ liệu đầu vào, giá trị băm thường thay đổi trên nhiều vị trí bit, thể hiện hiệu ứng avalanche.

RSA-PSS kết hợp SHA-256 giúp tạo và xác minh chữ ký số. Vì PSS sử dụng salt ngẫu nhiên nên cùng một dữ liệu và cùng khóa bí mật có thể cho ra các chữ ký khác nhau ở những lần ký khác nhau. Điều cần kiểm tra là chữ ký vẫn hợp lệ với đúng dữ liệu và khóa công khai tương ứng; nếu dữ liệu bị thay đổi, xác minh chữ ký cũ phải thất bại.

### 8.4. Kết luận

Bài tập giúp thực hành quy trình quản lý cặp khóa RSA, đọc cấu trúc PEM, mã hóa và giải mã dữ liệu nhỏ, đo hiệu năng, tính SHA-256 và tạo chữ ký số. Qua thử nghiệm, cần phân biệt rõ mục tiêu của từng cơ chế: RSA-OAEP dùng để mã hóa dữ liệu nhỏ, SHA-256 dùng để tạo giá trị băm, còn RSA-PSS dùng để tạo và xác minh chữ ký số.

## 9. Lưu ý bảo mật

  * Không gửi hoặc tải tệp `khoa_bi_mat.pem` lên kho mã nguồn công khai.
  * Khi chụp ảnh phần phân tích khóa bí mật, chỉ sử dụng khóa tạo cho bài thực hành và che/cắt các giá trị bí mật dài.
  * Base64 không bảo vệ tính bí mật của dữ liệu. Bản mã Base64 có thể lưu trữ hoặc truyền đi, nhưng khóa bí mật phải được giữ an toàn.
  * Không sử dụng RSA-OAEP để mã hóa trực tiếp dữ liệu lớn. Trong ứng dụng thực tế, nên dùng mô hình kết hợp: AES mã hóa dữ liệu, RSA bảo vệ khóa AES.
  * Không tự xây dựng chữ ký bằng phép toán RSA thô. Sử dụng API ký/xác minh chuẩn với RSA-PSS và SHA-256.

## 10. Tài liệu tham khảo

  * RFC 7468 — *Textual Encodings of PKIX, PKCS, and CMS Structures*: https://www.rfc-editor.org/rfc/rfc7468.html
  * RFC 8017 — *PKCS #1: RSA Cryptography Specifications*: https://www.rfc-editor.org/rfc/rfc8017.html
  * Microsoft Learn — `RSA.ImportFromPem`: https://learn.microsoft.com/en-us/dotnet/api/system.security.cryptography.rsa.importfrompem
  * Microsoft Learn — `RSA.SignData`: https://learn.microsoft.com/en-us/dotnet/api/system.security.cryptography.rsa.signdata
  * Microsoft Learn — `RSASignaturePadding.Pss`: https://learn.microsoft.com/en-us/dotnet/api/system.security.cryptography.rsasignaturepadding.pss
