using System.Text;

namespace Bai2_MaHoaRSA;

/// <summary>
/// Đọc cấu trúc DER theo dạng ASN.1 TLV (Tag - Length - Value).
/// Hiển thị vị trí byte, mã thẻ, độ dài và ý nghĩa trường trong các định dạng khóa RSA phổ biến.
/// Phục vụ học tập, không thay thế bộ phân tích khóa mật mã.
/// </summary>
public static class DerStructureInspector
{
    public static string Inspect(byte[] der, string pemLabel, int maximumNodes = 100, int maximumDepth = 10)
    {
        ArgumentNullException.ThrowIfNull(der);
        if (der.Length == 0)
            throw new FormatException("Dữ liệu DER đang rỗng.");

        string rootContext = pemLabel switch
        {
            "PUBLIC KEY" => "SPKI",
            "RSA PUBLIC KEY" => "RSAPublicKey",
            "PRIVATE KEY" => "PKCS8",
            "RSA PRIVATE KEY" => "RSAPrivateKey",
            _ => "GENERIC"
        };

        StringBuilder output = new();
        int nodeCount = 0;
        ParseRange(der, 0, der.Length, 0, "ROOT", rootContext, pemLabel,
            maximumNodes, maximumDepth, ref nodeCount, output);

        if (nodeCount >= maximumNodes)
            output.AppendLine($"... Đã giới hạn ở {maximumNodes} trường để kết quả dễ đọc.");

        output.AppendLine();
        output.AppendLine("Cách đọc: Vị trí tính từ byte 0 của DER; phần đầu gồm mã thẻ và độ dài; giá trị là phần dữ liệu theo sau phần đầu.");
        output.AppendLine("Các byte của PEM dạng chữ không ánh xạ trực tiếp 1-1 với trường RSA; cần giải mã Base64 trước để xem cấu trúc DER này.");
        return output.ToString();
    }

    private static void ParseRange(
        byte[] data,
        int start,
        int end,
        int depth,
        string parentContext,
        string rootContext,
        string pemLabel,
        int maximumNodes,
        int maximumDepth,
        ref int nodeCount,
        StringBuilder output)
    {
        if (depth > maximumDepth)
        {
            output.AppendLine(new string(' ', depth * 2) + "... Đã dừng phân tích do cấu trúc lồng quá sâu.");
            return;
        }

        int offset = start;
        int childIndex = 0;
        while (offset < end)
        {
            if (nodeCount >= maximumNodes)
                return;

            int nodeStart = offset;
            int tagStart = offset;
            byte firstTag = data[offset++];
            int tagClass = (firstTag >> 6) & 0x03;
            bool constructed = (firstTag & 0x20) != 0;
            int tagNumber = firstTag & 0x1F;

            if (tagNumber == 0x1F)
            {
                tagNumber = 0;
                int extraTagBytes = 0;
                bool tagComplete = false;
                while (offset < end && extraTagBytes < 5)
                {
                    byte tagByte = data[offset++];
                    extraTagBytes++;
                    tagNumber = checked((tagNumber << 7) | (tagByte & 0x7F));
                    if ((tagByte & 0x80) == 0)
                    {
                        tagComplete = true;
                        break;
                    }
                }
                if (!tagComplete)
                    throw new FormatException($"Mã thẻ ASN.1 không hợp lệ tại vị trí 0x{nodeStart:X4}.");
            }

            int tagEnd = offset;
            if (offset >= end)
                throw new FormatException($"Thiếu byte độ dài tại vị trí 0x{nodeStart:X4}.");

            byte firstLength = data[offset++];
            int valueLength;
            if ((firstLength & 0x80) == 0)
            {
                valueLength = firstLength;
            }
            else
            {
                int lengthByteCount = firstLength & 0x7F;
                if (lengthByteCount == 0)
                    throw new FormatException("DER không cho phép độ dài không xác định.");
                if (lengthByteCount > 4 || offset + lengthByteCount > end)
                    throw new FormatException($"Trường độ dài không hợp lệ tại vị trí 0x{nodeStart:X4}.");

                long lengthValue = 0;
                for (int i = 0; i < lengthByteCount; i++)
                    lengthValue = (lengthValue << 8) | data[offset++];
                if (lengthValue > int.MaxValue)
                    throw new FormatException("Độ dài trường DER vượt quá giới hạn hỗ trợ.");
                valueLength = (int)lengthValue;
            }

            int contentStart = offset;
            int contentEnd;
            try { contentEnd = checked(contentStart + valueLength); }
            catch (OverflowException ex) { throw new FormatException("Độ dài trường DER không hợp lệ.", ex); }
            if (contentEnd > end)
                throw new FormatException($"Trường tại vị trí 0x{nodeStart:X4} vượt quá vùng DER cha.");

            int headerLength = contentStart - nodeStart;
            byte[] tagBytes = data[tagStart..tagEnd];
            string tagName = GetTagName(tagClass, tagNumber, constructed);
            string indent = new(' ', depth * 2);
            string meaning = GetFieldMeaning(parentContext, childIndex, tagClass, tagNumber, pemLabel);
            string valueDescription = GetValueDescription(data, contentStart, valueLength, tagClass, tagNumber);

            output.Append(indent)
                .Append("Vị trí 0x").Append(nodeStart.ToString("X4"))
                .Append(" | ").Append(tagName)
                .Append(" | Mã thẻ (Tag): ").Append(Convert.ToHexString(tagBytes))
                .Append(" | Phần đầu: ").Append(headerLength).Append(" byte")
                .Append(" | Giá trị: ").Append(valueLength).Append(" byte");
            if (!string.IsNullOrWhiteSpace(meaning))
                output.Append(" | Ý nghĩa: ").Append(meaning);
            if (!string.IsNullOrWhiteSpace(valueDescription))
                output.Append(" | ").Append(valueDescription);
            output.AppendLine();
            nodeCount++;

            if (constructed)
            {
                string childContext = GetConstructedChildContext(parentContext, childIndex, rootContext, tagClass, tagNumber, pemLabel);
                ParseRange(data, contentStart, contentEnd, depth + 1, childContext, rootContext, pemLabel,
                    maximumNodes, maximumDepth, ref nodeCount, output);
            }
            else if (tagClass == 0 && tagNumber == 3 && valueLength >= 2)
            {
                // BIT STRING: byte đầu tiên là số bit không sử dụng ở cuối.
                // Với PUBLIC KEY, phần sau byte này chứa RSAPublicKey DER.
                int unusedBits = data[contentStart];
                int embeddedStart = contentStart + 1;
                if (unusedBits == 0 && embeddedStart < contentEnd && data[embeddedStart] == 0x30)
                {
                    string childContext = parentContext == "SPKI" ? "RSAPublicKey" : "GENERIC";
                    ParseRange(data, embeddedStart, contentEnd, depth + 1, childContext, rootContext, pemLabel,
                        maximumNodes, maximumDepth, ref nodeCount, output);
                }
            }
            else if (tagClass == 0 && tagNumber == 4 && valueLength > 2)
            {
                // PKCS#8 đặt cấu trúc RSAPrivateKey DER bên trong OCTET STRING.
                if (data[contentStart] == 0x30)
                {
                    string childContext = parentContext == "PKCS8" ? "RSAPrivateKey" : "GENERIC";
                    ParseRange(data, contentStart, contentEnd, depth + 1, childContext, rootContext, pemLabel,
                        maximumNodes, maximumDepth, ref nodeCount, output);
                }
            }

            offset = contentEnd;
            childIndex++;
        }
    }

    private static string GetConstructedChildContext(
        string parentContext,
        int childIndex,
        string rootContext,
        int tagClass,
        int tagNumber,
        string pemLabel)
    {
        if (parentContext == "ROOT" && childIndex == 0 && tagClass == 0 && tagNumber == 16)
            return rootContext;

        if (parentContext == "SPKI" && childIndex == 0 && tagClass == 0 && tagNumber == 16)
            return "AlgorithmIdentifier";

        if (parentContext == "PKCS8" && childIndex == 1 && tagClass == 0 && tagNumber == 16)
            return "AlgorithmIdentifier";

        // Public/private key có thể chứa một SEQUENCE DER lồng bên trong BIT STRING/OCTET STRING.
        if (parentContext == "RSAPublicKey" && pemLabel == "PUBLIC KEY" && childIndex == 0 && tagClass == 0 && tagNumber == 16)
            return "RSAPublicKey";
        if (parentContext == "RSAPrivateKey" && pemLabel == "PRIVATE KEY" && childIndex == 0 && tagClass == 0 && tagNumber == 16)
            return "RSAPrivateKey";

        return "GENERIC";
    }

    private static string GetFieldMeaning(string context, int index, int tagClass, int tagNumber, string pemLabel)
    {
        if (context == "ROOT")
        {
            return pemLabel switch
            {
                "PUBLIC KEY" => "SEQUENCE ngoài - SubjectPublicKeyInfo",
                "RSA PUBLIC KEY" => "SEQUENCE gốc - RSAPublicKey theo PKCS#1",
                "PRIVATE KEY" => "SEQUENCE ngoài - PrivateKeyInfo theo PKCS#8",
                "RSA PRIVATE KEY" => "SEQUENCE gốc - RSAPrivateKey theo PKCS#1",
                _ => "Cấu trúc DER gốc"
            };
        }

        if (context == "SPKI")
        {
            if (index == 0 && tagNumber == 16) return "AlgorithmIdentifier - thông tin thuật toán";
            if (index == 1 && tagNumber == 3) return "BIT STRING chứa cấu trúc RSAPublicKey";
        }

        if (context == "AlgorithmIdentifier")
        {
            if (index == 0 && tagNumber == 6) return "OID nhận diện thuật toán RSA";
            if (index == 1 && tagNumber == 5) return "Tham số thuật toán NULL";
        }

        if (context == "PKCS8")
        {
            if (index == 0 && tagNumber == 2) return "Phiên bản PKCS#8";
            if (index == 1 && tagNumber == 16) return "AlgorithmIdentifier - thông tin thuật toán";
            if (index == 2 && tagNumber == 4) return "OCTET STRING chứa khóa RSA bí mật dạng DER";
        }

        if (context == "RSAPublicKey")
        {
            if (pemLabel == "PUBLIC KEY" && index == 0 && tagNumber == 16)
                return "SEQUENCE chứa các tham số khóa công khai RSA";
            if (index == 0 && tagNumber == 2) return "n - mô-đun RSA";
            if (index == 1 && tagNumber == 2) return "e - số mũ công khai";
        }

        if (context == "RSAPrivateKey")
        {
            if (pemLabel == "PRIVATE KEY" && index == 0 && tagNumber == 2)
                return "Phiên bản của cấu trúc RSAPrivateKey";
            string[] fields = { "Phiên bản RSAPrivateKey", "n - mô-đun RSA", "e - số mũ công khai", "d - số mũ bí mật", "p - số nguyên tố bí mật thứ nhất", "q - số nguyên tố bí mật thứ hai", "dp - số mũ rút gọn theo p", "dq - số mũ rút gọn theo q", "inverseQ - nghịch đảo mô-đun dùng tối ưu phép toán" };
            if (index < fields.Length && tagClass == 0 && tagNumber == 2)
                return fields[index];
        }

        return string.Empty;
    }

    private static string GetTagName(int tagClass, int tagNumber, bool constructed)
    {
        if (tagClass == 0)
        {
            return tagNumber switch
            {
                2 => "INTEGER",
                3 => "BIT STRING",
                4 => "OCTET STRING",
                5 => "NULL",
                6 => "OBJECT IDENTIFIER",
                12 => "UTF8String",
                16 => "SEQUENCE",
                17 => "SET",
                19 => "PrintableString",
                22 => "IA5String",
                23 => "UTCTime",
                24 => "GeneralizedTime",
                _ => $"Thẻ phổ quát số {tagNumber}"
            };
        }

        string className = tagClass switch
        {
            1 => "LỚP ỨNG DỤNG (APPLICATION)",
            2 => "LỚP NGỮ CẢNH (CONTEXT-SPECIFIC)",
            3 => "LỚP RIÊNG (PRIVATE)",
            _ => "LỚP KHÔNG XÁC ĐỊNH (UNKNOWN)"
        };
        return $"{className} [{tagNumber}]{(constructed ? " (constructed)" : string.Empty)}";
    }

    private static string GetValueDescription(byte[] data, int start, int length, int tagClass, int tagNumber)
    {
        if (length == 0)
            return "giá trị rỗng";

        if (tagClass == 0 && tagNumber == 6)
        {
            try { return "OID = " + DecodeObjectIdentifier(data, start, length); }
            catch { return "OID (không giải mã được phần hiển thị)"; }
        }

        if (tagClass == 0 && tagNumber == 2)
        {
            int shown = Math.Min(length, 12);
            string preview = Convert.ToHexString(data.AsSpan(start, shown));
            if (length > shown) preview += "...";
            return $"INTEGER, byte đầu = {preview}";
        }

        if (tagClass == 0 && tagNumber == 3)
            return $"BIT STRING, byte đầu (số bit không sử dụng) = {data[start]}";

        if (tagClass == 0 && tagNumber == 5)
            return "NULL";

        return string.Empty;
    }

    private static string DecodeObjectIdentifier(byte[] data, int start, int length)
    {
        if (length == 0)
            throw new FormatException("OID rỗng.");

        List<ulong> values = new();
        ulong current = 0;
        for (int i = start; i < start + length; i++)
        {
            byte b = data[i];
            if (current > (ulong.MaxValue >> 7))
                throw new FormatException("OID quá lớn.");
            current = (current << 7) | (uint)(b & 0x7F);
            if ((b & 0x80) == 0)
            {
                values.Add(current);
                current = 0;
            }
        }
        if ((data[start + length - 1] & 0x80) != 0 || values.Count == 0)
            throw new FormatException("OID thiếu byte kết thúc.");

        ulong firstCombined = values[0];
        ulong firstArc = firstCombined < 40 ? 0UL : firstCombined < 80 ? 1UL : 2UL;
        ulong secondArc = firstCombined - firstArc * 40;
        StringBuilder result = new();
        result.Append(firstArc).Append('.').Append(secondArc);
        for (int i = 1; i < values.Count; i++)
            result.Append('.').Append(values[i]);
        return result.ToString();
    }
}
