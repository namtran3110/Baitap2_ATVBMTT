# DANH SÁCH KIỂM THỬ – BÀI 2 RSA, SHA-256 VÀ CHỮ KÝ SỐ

Đánh dấu kết quả sau khi chạy trên máy Windows của bạn. Không đánh dấu **Đạt** nếu chưa thực hiện kiểm thử.

| STT | Chức năng | Cách kiểm thử | Kết quả mong đợi | Kết quả thực tế |
|---:|---|---|---|---|
| 1 | Tạo cặp khóa | Tạo RSA-2048 | Có khóa công khai và khóa bí mật | Chưa thử |
| 2 | Xuất PEM công khai | Lưu khóa công khai ra tệp | Tệp có nhãn `BEGIN PUBLIC KEY` và `END PUBLIC KEY` | Chưa thử |
| 3 | Xuất PEM bí mật | Lưu khóa bí mật ra tệp | Tệp có nhãn `BEGIN PRIVATE KEY` và `END PRIVATE KEY` | Chưa thử |
| 4 | Nhập PEM công khai | Nhập lại từ tệp vừa xuất | Trạng thái cho biết đã nạp khóa công khai | Chưa thử |
| 5 | Nhập PEM bí mật | Nhập lại từ tệp vừa xuất | Trạng thái cho biết đã nạp khóa bí mật | Chưa thử |
| 6 | Kiểm tra cặp khóa | Nhập public/private cùng một cặp | Hiển thị cặp khóa khớp | Chưa thử |
| 7 | Kiểm tra khóa không cùng cặp | Nhập public key của cặp A và private key của cặp B | Hiển thị cảnh báo hai khóa không cùng cặp | Chưa thử |
| 8 | Phân tích PEM công khai | Nạp PEM và chọn phân tích | Hiển thị nhãn, số byte DER, cây TLV, `n` và `e` | Chưa thử |
| 9 | Phân tích PEM bí mật | Nạp PEM và chọn phân tích | Hiển thị cây TLV và các tham số `n`, `e`, `d`, `p`, `q`... | Chưa thử |
| 10 | Kiểm tra PEM lỗi | Xóa dòng END hoặc sửa Base64 rồi phân tích | Báo dữ liệu PEM không hợp lệ | Chưa thử |
| 11 | Mã hóa văn bản | Mã hóa văn bản ngắn bằng public key | Tạo bản mã Base64 | Chưa thử |
| 12 | Đếm byte UTF-8 | Nhập văn bản có tiếng Việt | Hiển thị số byte UTF-8, không chỉ đếm ký tự | Chưa thử |
| 13 | Giới hạn dữ liệu | Nhập dữ liệu UTF-8 vượt 190 byte với RSA-2048 | Ứng dụng từ chối và báo giới hạn | Chưa thử |
| 14 | Mã hóa khóa AES mẫu | Tạo khóa AES-256 mẫu và chọn mã hóa | Mảng 32 byte nhị phân được mã hóa | Chưa thử |
| 15 | Lưu bản mã | Lưu kết quả ra tệp `.b64` | Tệp chứa Base64 hợp lệ | Chưa thử |
| 16 | Giải mã và so sánh | Giải mã với private key đúng | Dữ liệu nguồn và dữ liệu giải mã giống hệt theo byte | Chưa thử |
| 17 | Giải mã sai khóa | Dùng private key không tương ứng | Giải mã thất bại | Chưa thử |
| 18 | Đo tốc độ RSA | Chạy 100 hoặc 1.000 lần | Hiển thị thời gian mã hóa, giải mã, ký và xác minh | Chưa thử |
| 19 | SHA-256 | Thay đổi một ký tự đầu vào | Chuỗi băm được cập nhật | Chưa thử |
| 20 | Hiệu ứng avalanche | So sánh A và B chỉ khác một ký tự | Hiển thị số bit khác nhau trên 256 bit | Chưa thử |
| 21 | Ký số lần đầu | Ký dữ liệu bằng private key | Tạo chữ ký RSA-PSS | Chưa thử |
| 22 | Ký lại cùng dữ liệu/cùng khóa | Ký lần thứ hai mà không đổi dữ liệu hoặc private key | Chữ ký thường khác lần trước và trạng thái báo kiểm tra được tính ngẫu nhiên | Chưa thử |
| 23 | Xác minh chữ ký đúng | Xác minh bằng public key tương ứng | Báo chữ ký hợp lệ | Chưa thử |
| 24 | Sửa dữ liệu sau khi ký | Thay đổi một ký tự rồi xác minh chữ ký cũ | Báo chữ ký không hợp lệ | Chưa thử |
| 25 | Xác minh bằng khóa khác | Dùng public key không tương ứng | Xác minh thất bại | Chưa thử |
| 26 | Mã hóa mảng byte tùy ý | Nhập Base64 `AAECAwQF`, mã hóa rồi giải mã | Thu lại đúng các byte `00 01 02 03 04 05`; so sánh báo giống hệt | Chưa thử |
| 27 | Base64 nguồn không hợp lệ | Nhập chuỗi như `ABC!` vào ô mảng byte Base64 | Giao diện báo Base64 chưa hợp lệ; không làm ứng dụng thoát | Chưa thử |

## Mẫu ghi số liệu tốc độ

| Kích thước khóa | Số lần lặp | Mã hóa công khai (ms/lần) | Giải mã bí mật (ms/lần) | Ký RSA-PSS (ms/lần) | Xác minh (ms/lần) |
|---|---:|---:|---:|---:|---:|
| RSA-2048 | 100 | Điền số liệu | Điền số liệu | Điền số liệu | Điền số liệu |
| RSA-3072 | 100 | Điền số liệu | Điền số liệu | Điền số liệu | Điền số liệu |
| RSA-4096 | 100 | Điền số liệu | Điền số liệu | Điền số liệu | Điền số liệu |

Chỉ so sánh số liệu khi dùng cùng máy, cùng dữ liệu, cùng số lần lặp và điều kiện tương đương. Không điền số liệu giả định vào báo cáo.
