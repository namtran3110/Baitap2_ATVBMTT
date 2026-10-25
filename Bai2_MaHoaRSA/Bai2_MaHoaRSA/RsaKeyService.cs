using System.Numerics;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;

namespace Bai2_MaHoaRSA;

/// <summary>
/// Các thao tác tạo, xuất, nhập và phân tích khóa RSA/PEM.
/// </summary>
public static class RsaKeyService
{
    private static readonly Regex BeginRegex = new("-----BEGIN ([A-Z0-9 ]+)-----", RegexOptions.Compiled);

    public static RSA CreateKeyPair(int keySize)
    {
        if (keySize is not (2048 or 3072 or 4096))
            throw new ArgumentOutOfRangeException(nameof(keySize), "Kích thước khóa được hỗ trợ: 2048, 3072 hoặc 4096 bit.");

        RSA rsa = RSA.Create();
        rsa.KeySize = keySize;
        return rsa;
    }

    public static RSA CreatePublicOnly(RSA privateKey)
    {
        RSA publicKey = RSA.Create();
        publicKey.ImportParameters(privateKey.ExportParameters(false));
        return publicKey;
    }

    public static string ExportPublicPem(RSA rsa) => rsa.ExportSubjectPublicKeyInfoPem();

    public static string ExportPrivatePem(RSA rsa) => rsa.ExportPkcs8PrivateKeyPem();

    public static RSA ImportPublicPem(string pem)
    {
        string label = GetPemLabel(pem);
        if (label is not ("PUBLIC KEY" or "RSA PUBLIC KEY"))
            throw new CryptographicException("Hãy chọn PEM khóa công khai: PUBLIC KEY hoặc RSA PUBLIC KEY.");
        _ = ExtractDerFromPem(pem, label, out _);

        RSA rsa = RSA.Create();
        try
        {
            rsa.ImportFromPem(pem);
            return rsa;
        }
        catch
        {
            rsa.Dispose();
            throw;
        }
    }

    public static RSA ImportPrivatePem(string pem)
    {
        string label = GetPemLabel(pem);
        if (label is not ("PRIVATE KEY" or "RSA PRIVATE KEY"))
            throw new CryptographicException("Hãy chọn PEM khóa bí mật: PRIVATE KEY hoặc RSA PRIVATE KEY. Chưa hỗ trợ khóa bí mật được mã hóa bằng mật khẩu.");
        _ = ExtractDerFromPem(pem, label, out _);

        RSA rsa = RSA.Create();
        try
        {
            rsa.ImportFromPem(pem);
            RSAParameters p = rsa.ExportParameters(true);
            if (p.D is null || p.D.Length == 0)
                throw new CryptographicException("PEM không chứa khóa bí mật.");
            return rsa;
        }
        catch
        {
            rsa.Dispose();
            throw;
        }
    }

    public static string GetPemLabel(string pem)
    {
        Match match = BeginRegex.Match(pem ?? string.Empty);
        if (!match.Success)
            throw new FormatException("Không tìm thấy dòng BEGIN trong nội dung PEM.");
        return match.Groups[1].Value.Trim();
    }

    public static string AnalyzePem(string pem)
    {
        if (string.IsNullOrWhiteSpace(pem))
            throw new ArgumentException("Nội dung PEM đang rỗng.", nameof(pem));

        string label = GetPemLabel(pem);
        byte[] der = ExtractDerFromPem(pem, label, out string base64Body);

        using RSA rsa = RSA.Create();
        rsa.ImportFromPem(pem);
        bool isPrivate = label is "PRIVATE KEY" or "RSA PRIVATE KEY";
        RSAParameters p = rsa.ExportParameters(isPrivate);

        StringBuilder sb = new();
        sb.AppendLine("PHÂN TÍCH PEM");
        sb.AppendLine("========================================");
        sb.AppendLine($"Nhãn PEM: {label}");
        sb.AppendLine($"Số ký tự Base64 (không tính xuống dòng): {base64Body.Length}");
        sb.AppendLine($"Độ dài DER sau khi giải mã Base64: {der.Length} byte");
        sb.AppendLine($"Kích thước khóa RSA: {rsa.KeySize} bit");
        sb.AppendLine();
        sb.AppendLine("Ý NGHĨA CẤU TRÚC:");
        sb.AppendLine(GetStructureDescription(label));
        sb.AppendLine();
        sb.AppendLine("CÂY CẤU TRÚC DER/ASN.1 THEO VỊ TRÍ BYTE:");
        sb.AppendLine(DerStructureInspector.Inspect(der, label));
        sb.AppendLine();
        sb.AppendLine("CÁC TRƯỜNG THEO ĐỊNH DẠNG PEM:");
        sb.AppendLine(GetFieldDescription(label));
        sb.AppendLine();
        sb.AppendLine("256 byte DER đầu tiên (HEX, nếu dữ liệu ngắn hơn thì hiển thị toàn bộ):");
        sb.AppendLine(FormatHex(der.Take(Math.Min(256, der.Length)).ToArray()));
        if (der.Length > 256)
            sb.AppendLine("... (đã rút gọn phần HEX; cấu trúc TLV phía trên vẫn hiển thị độ dài các trường)");
        sb.AppendLine();
        sb.AppendLine("CÁC THAM SỐ RSA ĐÃ ĐỌC ĐƯỢC:");
        sb.AppendLine(DescribeParameters(p, isPrivate, rsa.KeySize));
        sb.AppendLine();
        sb.AppendLine("Lưu ý: Base64 chỉ là cách biểu diễn byte; PEM không tự mã hóa để bảo vệ khóa bí mật.");
        return sb.ToString();
    }

    private static byte[] ExtractDerFromPem(string pem, string expectedLabel, out string base64Body)
    {
        Match begin = BeginRegex.Match(pem);
        if (!begin.Success)
            throw new FormatException("Không tìm thấy dòng BEGIN trong nội dung PEM.");

        string label = begin.Groups[1].Value.Trim();
        if (!string.Equals(label, expectedLabel, StringComparison.Ordinal))
            throw new FormatException("Nhãn PEM không nhất quán.");

        Regex endRegex = new("-----END ([A-Z0-9 ]+)-----", RegexOptions.Compiled);
        Match end = endRegex.Match(pem, begin.Index + begin.Length);
        if (!end.Success)
            throw new FormatException("Không tìm thấy dòng END tương ứng trong nội dung PEM.");
        if (!string.Equals(end.Groups[1].Value.Trim(), label, StringComparison.Ordinal))
            throw new FormatException("Nhãn BEGIN và END trong PEM không khớp nhau.");

        string body = pem.Substring(begin.Index + begin.Length, end.Index - (begin.Index + begin.Length));
        base64Body = Regex.Replace(body, @"\s+", string.Empty);
        if (base64Body.Length == 0)
            throw new FormatException("Phần dữ liệu Base64 trong PEM đang rỗng.");

        try
        {
            return Convert.FromBase64String(base64Body);
        }
        catch (FormatException ex)
        {
            throw new FormatException("Phần thân PEM không phải Base64 hợp lệ.", ex);
        }
    }

    private static string GetFieldDescription(string label) => label switch
    {
        "PUBLIC KEY" => "- SEQUENCE ngoài: bao bọc SubjectPublicKeyInfo.\r\n" +
                        "- SEQUENCE AlgorithmIdentifier: mô tả thuật toán RSA; OID rsaEncryption thường là 1.2.840.113549.1.1.1.\r\n" +
                        "- BIT STRING: byte đầu cho biết số bit không sử dụng; phần còn lại chứa RSAPublicKey DER.\r\n" +
                        "- RSAPublicKey: INTEGER đầu tiên là n (mô-đun), INTEGER thứ hai là e (số mũ công khai).",
        "RSA PUBLIC KEY" => "- SEQUENCE PKCS#1 chứa trực tiếp hai trường INTEGER: n (mô-đun) và e (số mũ công khai).",
        "PRIVATE KEY" => "- SEQUENCE ngoài: cấu trúc PKCS#8 PrivateKeyInfo.\r\n" +
                         "- INTEGER đầu tiên: phiên bản.\r\n" +
                         "- SEQUENCE AlgorithmIdentifier: mô tả thuật toán RSA.\r\n" +
                         "- OCTET STRING: chứa cấu trúc RSAPrivateKey DER bên trong.\r\n" +
                         "- RSAPrivateKey bên trong: phiên bản, n, e, d, p, q, dp, dq và inverseQ theo thứ tự.",
        "RSA PRIVATE KEY" => "- SEQUENCE PKCS#1 chứa các INTEGER theo thứ tự: phiên bản, n, e, d, p, q, dp, dq, inverseQ.\r\n" +
                             "- n và e là thành phần công khai; d, p, q, dp, dq và inverseQ là các tham số bí mật.",
        _ => "Không có bảng diễn giải riêng cho nhãn PEM này. Ứng dụng hỗ trợ xem cấu trúc chung và tham số RSA nếu thư viện đọc được khóa."
    };

    public static string DescribeParameters(RSA rsa, bool includePrivate)
    {
        RSAParameters p = rsa.ExportParameters(includePrivate);
        return DescribeParameters(p, includePrivate, rsa.KeySize);
    }

    private static string DescribeParameters(RSAParameters p, bool includePrivate, int keySize)
    {
        StringBuilder sb = new();
        sb.AppendLine($"Kích thước khóa: {keySize} bit");
        sb.AppendLine("n (mô-đun) - số công khai chung của cặp khóa, dạng hex:");
        sb.AppendLine(FormatLongHex(p.Modulus));
        sb.AppendLine($"e (số mũ công khai): {ToUnsignedBigInteger(p.Exponent).ToString()}");
        sb.AppendLine($"e dạng hex: {FormatLongHex(p.Exponent)}");

        if (includePrivate)
        {
            sb.AppendLine("d (số mũ bí mật):");
            sb.AppendLine(FormatLongHex(p.D));
            sb.AppendLine("p và q - hai số nguyên tố bí mật tạo nên n:");
            sb.AppendLine($"p = {FormatLongHex(p.P)}");
            sb.AppendLine($"q = {FormatLongHex(p.Q)}");
            sb.AppendLine("dp, dq và inverseQ - các tham số tối ưu phép toán RSA:");
            sb.AppendLine($"dp = {FormatLongHex(p.DP)}");
            sb.AppendLine($"dq = {FormatLongHex(p.DQ)}");
            sb.AppendLine($"inverseQ = {FormatLongHex(p.InverseQ)}");
        }
        else
        {
            sb.AppendLine("Đây là khóa công khai; không có d, p, q trong đối tượng khóa công khai.");
        }
        return sb.ToString();
    }

    private static string GetStructureDescription(string label) => label switch
    {
        "PUBLIC KEY" => "SubjectPublicKeyInfo (SPKI): SEQUENCE bên ngoài chứa AlgorithmIdentifier (OID rsaEncryption và tham số) cùng BIT STRING. BIT STRING chứa RSAPublicKey gồm INTEGER n và INTEGER e.",
        "RSA PUBLIC KEY" => "PKCS#1 RSAPublicKey: SEQUENCE gồm INTEGER n (mô-đun) và INTEGER e (số mũ công khai).",
        "PRIVATE KEY" => "PKCS#8 PrivateKeyInfo: SEQUENCE gồm version, AlgorithmIdentifier và OCTET STRING. OCTET STRING chứa cấu trúc RSAPrivateKey với n, e, d, p, q, dp, dq, inverseQ.",
        "RSA PRIVATE KEY" => "PKCS#1 RSAPrivateKey: SEQUENCE gồm version, n, e, d, p, q, dp, dq, inverseQ và có thể có các tham số nguyên tố mở rộng.",
        "ENCRYPTED PRIVATE KEY" => "PKCS#8 EncryptedPrivateKeyInfo: dữ liệu khóa bí mật được bảo vệ bằng mật khẩu; ứng dụng mẫu này chưa hỗ trợ nhập định dạng này.",
        _ => "Nhãn PEM chưa được mô tả riêng. Hãy dùng PUBLIC KEY, RSA PUBLIC KEY, PRIVATE KEY hoặc RSA PRIVATE KEY."
    };

    private static BigInteger ToUnsignedBigInteger(byte[]? bytes)
    {
        if (bytes is null || bytes.Length == 0)
            return BigInteger.Zero;
        return new BigInteger(bytes, isUnsigned: true, isBigEndian: true);
    }

    private static string FormatLongHex(byte[]? bytes)
    {
        if (bytes is null || bytes.Length == 0)
            return "(không có)";
        string hex = Convert.ToHexString(bytes);
        return string.Join(Environment.NewLine, Enumerable.Range(0, (hex.Length + 63) / 64)
            .Select(i => hex.Substring(i * 64, Math.Min(64, hex.Length - i * 64))));
    }

    private static string FormatHex(byte[] bytes)
    {
        return string.Join(Environment.NewLine, bytes.Select((b, i) => new { b, i })
            .GroupBy(x => x.i / 16)
            .Select(g => string.Join(" ", g.Select(x => x.b.ToString("X2")))));
    }
}
