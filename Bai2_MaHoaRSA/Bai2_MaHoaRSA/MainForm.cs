using System.Diagnostics;
using System.Security.Cryptography;
using System.Text;
using System.Windows.Forms;

namespace Bai2_MaHoaRSA;

public sealed class MainForm : Form
{
    private RSA? _publicRsa;
    private RSA? _privateRsa;
    private byte[]? _demoAesKey;
    private byte[]? _lastPlainData;
    private byte[]? _lastDecryptedData;
    private byte[]? _lastSignature;
    private byte[]? _lastSignedData;
    private string? _lastSigningKeyFingerprint;

    private readonly ComboBox _cmbKeySize = new();
    private readonly Label _lblPublicStatus = new();
    private readonly Label _lblPrivateStatus = new();
    private readonly TextBox _txtKeyDetails = new();
    private readonly TextBox _txtPemInput = new();
    private readonly TextBox _txtPemAnalysis = new();

    private readonly TextBox _txtPlainText = new();
    private readonly Label _lblInputByteCount = new();
    private readonly TextBox _txtByteArrayBase64 = new();
    private readonly Label _lblByteArrayBase64Count = new();
    private readonly Label _lblAesSample = new();
    private readonly TextBox _txtCipherBase64 = new();
    private readonly TextBox _txtDecryptedBase64 = new();
    private readonly TextBox _txtDecryptedText = new();
    private readonly Label _lblDataCompare = new();

    private readonly TextBox _txtHashA = new();
    private readonly TextBox _txtHashB = new();
    private readonly TextBox _txtHashOutA = new();
    private readonly TextBox _txtHashOutB = new();
    private readonly Label _lblHashDifference = new();

    private readonly TextBox _txtSignData = new();
    private readonly TextBox _txtSignature = new();
    private readonly Label _lblSignatureStatus = new();
    private readonly TextBox _txtBenchmarkData = new();
    private readonly NumericUpDown _numIterations = new();
    private readonly TextBox _txtBenchmarkResult = new();

    public MainForm()
    {
        Text = "Bài 2 - Mã hóa RSA, SHA-256 và chữ ký số";
        StartPosition = FormStartPosition.CenterScreen;
        Width = 1260;
        Height = 850;
        MinimumSize = new System.Drawing.Size(1000, 700);
        Font = new System.Drawing.Font("Segoe UI", 9F);
        BuildInterface();
        UpdateInputByteCount();
        UpdateHashes();
        RefreshKeyStatus();
    }

    private void BuildInterface()
    {
        TabControl tabs = new() { Dock = DockStyle.Fill };
        tabs.TabPages.Add(BuildKeyAndPemTab());
        tabs.TabPages.Add(BuildEncryptDecryptTab());
        tabs.TabPages.Add(BuildHashTab());
        tabs.TabPages.Add(BuildSignatureAndBenchmarkTab());
        Controls.Add(tabs);
    }

    private TabPage BuildKeyAndPemTab()
    {
        TabPage page = new("Khóa và PEM");
        FlowLayoutPanel flow = CreateFlowPanel();

        GroupBox createBox = CreateGroup("1. Tạo và xuất cặp khóa RSA", 1120, 112);
        AddLabel(createBox, "Kích thước khóa:", 18, 29, 105, 26);
        _cmbKeySize.SetBounds(125, 26, 120, 28);
        _cmbKeySize.DropDownStyle = ComboBoxStyle.DropDownList;
        _cmbKeySize.Items.AddRange(new object[] { "2048 bit", "3072 bit", "4096 bit" });
        _cmbKeySize.SelectedIndex = 0;
        createBox.Controls.Add(_cmbKeySize);
        createBox.Controls.Add(MakeButton("Sinh cặp khóa", 265, 25, 145, 32, GenerateKeyPair_Click));
        createBox.Controls.Add(MakeButton("Xuất PEM khóa công khai", 420, 25, 155, 32, (_, _) => ExportPublicKey()));
        createBox.Controls.Add(MakeButton("Xuất PEM khóa bí mật", 585, 25, 160, 32, (_, _) => ExportPrivateKey()));
        AddLabel(createBox, "Gợi ý: dùng RSA-2048 cho bài thử nghiệm giới hạn 190 byte với OAEP-SHA256.", 18, 69, 1060, 25);
        flow.Controls.Add(createBox);

        GroupBox importBox = CreateGroup("2. Nhập khóa từ tệp PEM và xem trạng thái", 1120, 165);
        importBox.Controls.Add(MakeButton("Nhập khóa công khai...", 18, 27, 165, 32, (_, _) => ImportPublicFromFile()));
        importBox.Controls.Add(MakeButton("Nhập khóa bí mật...", 190, 27, 170, 32, (_, _) => ImportPrivateFromFile()));
        _lblPublicStatus.SetBounds(375, 27, 700, 26);
        _lblPrivateStatus.SetBounds(375, 58, 700, 26);
        importBox.Controls.Add(_lblPublicStatus);
        importBox.Controls.Add(_lblPrivateStatus);
        _txtKeyDetails.SetBounds(18, 91, 1075, 58);
        _txtKeyDetails.Multiline = true;
        _txtKeyDetails.ReadOnly = true;
        _txtKeyDetails.ScrollBars = ScrollBars.Vertical;
        _txtKeyDetails.Anchor = AnchorStyles.Top | AnchorStyles.Left | AnchorStyles.Right;
        importBox.Controls.Add(_txtKeyDetails);
        flow.Controls.Add(importBox);

        GroupBox pemBox = CreateGroup("3. Xem nội dung PEM và phân tích các trường", 1120, 480);
        AddLabel(pemBox, "Nội dung PEM (có thể dán trực tiếp vào đây):", 18, 25, 500, 23);
        _txtPemInput.SetBounds(18, 50, 505, 300);
        _txtPemInput.Multiline = true;
        _txtPemInput.ScrollBars = ScrollBars.Both;
        _txtPemInput.WordWrap = false;
        _txtPemInput.Font = new System.Drawing.Font("Consolas", 9F);
        pemBox.Controls.Add(_txtPemInput);
        pemBox.Controls.Add(MakeButton("Nạp PEM từ tệp...", 18, 360, 160, 32, (_, _) => LoadPemTextFromFile()));
        pemBox.Controls.Add(MakeButton("Phân tích PEM", 185, 360, 145, 32, (_, _) => AnalyzePemText()));
        pemBox.Controls.Add(MakeButton("Nhập PEM này làm khóa công khai", 18, 400, 245, 32, (_, _) => ImportPublicFromText()));
        pemBox.Controls.Add(MakeButton("Nhập PEM này làm khóa bí mật", 270, 400, 255, 32, (_, _) => ImportPrivateFromText()));
        AddLabel(pemBox, "Kết quả phân tích:", 545, 25, 520, 23);
        _txtPemAnalysis.SetBounds(545, 50, 550, 382);
        _txtPemAnalysis.Multiline = true;
        _txtPemAnalysis.ReadOnly = true;
        _txtPemAnalysis.ScrollBars = ScrollBars.Both;
        _txtPemAnalysis.WordWrap = false;
        _txtPemAnalysis.Font = new System.Drawing.Font("Consolas", 8.5F);
        pemBox.Controls.Add(_txtPemAnalysis);
        AddLabel(pemBox, "PEM là định dạng văn bản bao ngoài dữ liệu Base64. Giải mã Base64 thu được DER/ASN.1; các trường RSA được hiển thị trong kết quả phân tích.", 18, 442, 1075, 26);
        flow.Controls.Add(pemBox);

        page.Controls.Add(flow);
        return page;
    }

    private TabPage BuildEncryptDecryptTab()
    {
        TabPage page = new("Mã hóa và giải mã");
        FlowLayoutPanel flow = CreateFlowPanel();

        GroupBox inputBox = CreateGroup("1. Dữ liệu nguồn (mảng byte tối đa 190 byte theo yêu cầu bài tập)", 1120, 260);
        AddLabel(inputBox, "Nhập văn bản UTF-8:", 18, 27, 300, 22);
        _txtPlainText.SetBounds(18, 52, 1075, 75);
        _txtPlainText.Multiline = true;
        _txtPlainText.ScrollBars = ScrollBars.Vertical;
        _txtPlainText.Text = "Dữ liệu thử nghiệm RSA";
        _txtPlainText.TextChanged += (_, _) => UpdateInputByteCount();
        inputBox.Controls.Add(_txtPlainText);
        _lblInputByteCount.SetBounds(18, 132, 1075, 23);
        inputBox.Controls.Add(_lblInputByteCount);
        inputBox.Controls.Add(MakeButton("Mã hóa văn bản", 18, 163, 155, 34, (_, _) => EncryptTextData()));
        inputBox.Controls.Add(MakeButton("Tạo khóa AES-256 mẫu (32 byte)", 185, 163, 250, 34, (_, _) => CreateAesDemoKey()));
        inputBox.Controls.Add(MakeButton("Mã hóa khóa AES mẫu", 445, 163, 195, 34, (_, _) => EncryptAesDemoKey()));
        _lblAesSample.SetBounds(18, 205, 1075, 42);
        inputBox.Controls.Add(_lblAesSample);
        flow.Controls.Add(inputBox);

        GroupBox byteArrayBox = CreateGroup("2. Mã hóa mảng byte tùy ý nhập dưới dạng Base64", 1120, 150);
        AddLabel(byteArrayBox, "Dán dữ liệu nguồn dạng Base64 (giải mã Base64 để lấy chính xác mảng byte cần mã hóa):", 18, 22, 1060, 22);
        _txtByteArrayBase64.SetBounds(18, 47, 800, 48);
        _txtByteArrayBase64.Multiline = true;
        _txtByteArrayBase64.ScrollBars = ScrollBars.Vertical;
        _txtByteArrayBase64.Font = new System.Drawing.Font("Consolas", 9F);
        _txtByteArrayBase64.TextChanged += (_, _) => UpdateByteArrayBase64Count();
        byteArrayBox.Controls.Add(_txtByteArrayBase64);
        _lblByteArrayBase64Count.SetBounds(830, 49, 265, 42);
        byteArrayBox.Controls.Add(_lblByteArrayBase64Count);
        byteArrayBox.Controls.Add(MakeButton("Mã hóa mảng byte Base64", 18, 103, 235, 32, (_, _) => EncryptByteArrayBase64()));
        flow.Controls.Add(byteArrayBox);

        GroupBox cipherBox = CreateGroup("3. Bản mã RSA (Base64)", 1120, 190);
        _txtCipherBase64.SetBounds(18, 27, 1075, 75);
        _txtCipherBase64.Multiline = true;
        _txtCipherBase64.ScrollBars = ScrollBars.Vertical;
        _txtCipherBase64.Font = new System.Drawing.Font("Consolas", 9F);
        cipherBox.Controls.Add(_txtCipherBase64);
        cipherBox.Controls.Add(MakeButton("Lưu bản mã ra tệp...", 18, 112, 180, 33, (_, _) => SaveCiphertextToFile()));
        cipherBox.Controls.Add(MakeButton("Giải mã bản mã hiện tại", 205, 112, 200, 33, (_, _) => DecryptCurrentCiphertext()));
        cipherBox.Controls.Add(MakeButton("Đọc tệp Base64 và giải mã...", 412, 112, 245, 33, (_, _) => DecryptCiphertextFromFile()));
        AddLabel(cipherBox, "RSA-OAEP-SHA256 với khóa 2048 bit tạo bản mã 256 byte; Base64 thường dài 344 ký tự.", 18, 151, 1075, 25);
        flow.Controls.Add(cipherBox);

        GroupBox resultBox = CreateGroup("4. Kết quả giải mã và đối chiếu dữ liệu", 1120, 245);
        AddLabel(resultBox, "Dữ liệu giải mã (Base64):", 18, 25, 500, 22);
        _txtDecryptedBase64.SetBounds(18, 49, 1075, 55);
        _txtDecryptedBase64.Multiline = true;
        _txtDecryptedBase64.ReadOnly = true;
        _txtDecryptedBase64.ScrollBars = ScrollBars.Vertical;
        _txtDecryptedBase64.Font = new System.Drawing.Font("Consolas", 9F);
        resultBox.Controls.Add(_txtDecryptedBase64);
        AddLabel(resultBox, "Dữ liệu đọc được dạng UTF-8 (nếu phù hợp):", 18, 109, 500, 22);
        _txtDecryptedText.SetBounds(18, 133, 1075, 48);
        _txtDecryptedText.Multiline = true;
        _txtDecryptedText.ReadOnly = true;
        _txtDecryptedText.ScrollBars = ScrollBars.Vertical;
        resultBox.Controls.Add(_txtDecryptedText);
        resultBox.Controls.Add(MakeButton("So sánh với dữ liệu nguồn", 18, 188, 215, 32, (_, _) => CompareCurrentData()));
        resultBox.Controls.Add(MakeButton("Lưu dữ liệu giải mã ra tệp...", 242, 188, 235, 32, (_, _) => SaveDecryptedData()));
        _lblDataCompare.SetBounds(495, 190, 600, 32);
        resultBox.Controls.Add(_lblDataCompare);
        flow.Controls.Add(resultBox);

        page.Controls.Add(flow);
        return page;
    }

    private TabPage BuildHashTab()
    {
        TabPage page = new("SHA-256");
        FlowLayoutPanel flow = CreateFlowPanel();
        GroupBox group = CreateGroup("Tính SHA-256 tự động khi thay đổi dữ liệu", 1120, 640);
        AddLabel(group, "Dữ liệu A:", 18, 25, 500, 22);
        _txtHashA.SetBounds(18, 50, 520, 105);
        _txtHashA.Multiline = true;
        _txtHashA.ScrollBars = ScrollBars.Vertical;
        _txtHashA.Text = "An toàn thông tin";
        _txtHashA.TextChanged += (_, _) => UpdateHashes();
        group.Controls.Add(_txtHashA);
        AddLabel(group, "SHA-256 của A (256 bit = 32 byte = 64 ký tự hex):", 18, 163, 520, 22);
        _txtHashOutA.SetBounds(18, 188, 520, 95);
        _txtHashOutA.Multiline = true;
        _txtHashOutA.ReadOnly = true;
        _txtHashOutA.WordWrap = true;
        group.Controls.Add(_txtHashOutA);

        AddLabel(group, "Dữ liệu B (hãy thay đổi rất ít so với A):", 560, 25, 530, 22);
        _txtHashB.SetBounds(560, 50, 530, 105);
        _txtHashB.Multiline = true;
        _txtHashB.ScrollBars = ScrollBars.Vertical;
        _txtHashB.Text = "An toàn thông tin!";
        _txtHashB.TextChanged += (_, _) => UpdateHashes();
        group.Controls.Add(_txtHashB);
        AddLabel(group, "SHA-256 của B:", 560, 163, 530, 22);
        _txtHashOutB.SetBounds(560, 188, 530, 95);
        _txtHashOutB.Multiline = true;
        _txtHashOutB.ReadOnly = true;
        _txtHashOutB.WordWrap = true;
        group.Controls.Add(_txtHashOutB);

        GroupBox compareBox = CreateGroup("Đánh giá mức độ thay đổi giữa hai chuỗi băm", 1075, 150);
        compareBox.SetBounds(18, 305, 1075, 150);
        _lblHashDifference.SetBounds(20, 35, 1020, 55);
        compareBox.Controls.Add(_lblHashDifference);
        AddLabel(compareBox, "Số bit khác nhau được đếm trên 256 bit đầu ra. Khoảng 128 bit là giá trị kỳ vọng thống kê, không phải kết quả bắt buộc cho mọi cặp đầu vào.", 20, 93, 1030, 45);
        group.Controls.Add(compareBox);

        AddLabel(group, "Nhận xét: SHA-256 là hàm băm một chiều, không phải mã hóa. Một thay đổi nhỏ ở đầu vào thường làm đầu ra thay đổi mạnh (hiệu ứng avalanche).", 18, 485, 1075, 65);
        flow.Controls.Add(group);
        page.Controls.Add(flow);
        return page;
    }

    private TabPage BuildSignatureAndBenchmarkTab()
    {
        TabPage page = new("Chữ ký số và tốc độ");
        FlowLayoutPanel flow = CreateFlowPanel();

        GroupBox signBox = CreateGroup("1. Ký dữ liệu bằng khóa bí mật và xác minh bằng khóa công khai", 1120, 355);
        AddLabel(signBox, "Dữ liệu cần ký (UTF-8):", 18, 25, 500, 22);
        _txtSignData.SetBounds(18, 50, 1075, 75);
        _txtSignData.Multiline = true;
        _txtSignData.ScrollBars = ScrollBars.Vertical;
        _txtSignData.Text = "Dữ liệu cần ký số";
        signBox.Controls.Add(_txtSignData);
        signBox.Controls.Add(MakeButton("Ký bằng khóa bí mật (RSA-PSS)", 18, 136, 255, 34, (_, _) => SignCurrentData()));
        signBox.Controls.Add(MakeButton("Lưu chữ ký ra tệp...", 285, 136, 185, 34, (_, _) => SaveSignatureToFile()));
        signBox.Controls.Add(MakeButton("Xác minh chữ ký", 482, 136, 170, 34, (_, _) => VerifyCurrentSignature()));
        AddLabel(signBox, "Chữ ký Base64:", 18, 179, 500, 22);
        _txtSignature.SetBounds(18, 203, 1075, 85);
        _txtSignature.Multiline = true;
        _txtSignature.ScrollBars = ScrollBars.Vertical;
        _txtSignature.Font = new System.Drawing.Font("Consolas", 9F);
        signBox.Controls.Add(_txtSignature);
        _lblSignatureStatus.SetBounds(18, 297, 1075, 45);
        signBox.Controls.Add(_lblSignatureStatus);
        flow.Controls.Add(signBox);

        GroupBox benchBox = CreateGroup("2. Đo tốc độ mã hóa/giải mã và ký/xác minh RSA", 1120, 315);
        AddLabel(benchBox, "Dữ liệu thử nghiệm UTF-8 (mã hóa RSA tối đa 190 byte):", 18, 25, 650, 22);
        _txtBenchmarkData.SetBounds(18, 50, 1075, 55);
        _txtBenchmarkData.Multiline = true;
        _txtBenchmarkData.Text = "Dữ liệu đo tốc độ RSA";
        benchBox.Controls.Add(_txtBenchmarkData);
        AddLabel(benchBox, "Số lần lặp:", 18, 118, 95, 24);
        _numIterations.SetBounds(112, 115, 115, 28);
        _numIterations.Minimum = 1;
        _numIterations.Maximum = 100000;
        _numIterations.Value = 100;
        benchBox.Controls.Add(_numIterations);
        benchBox.Controls.Add(MakeButton("Chạy đo tốc độ", 245, 112, 170, 34, (_, _) => RunBenchmark()));
        _txtBenchmarkResult.SetBounds(18, 155, 1075, 145);
        _txtBenchmarkResult.Multiline = true;
        _txtBenchmarkResult.ReadOnly = true;
        _txtBenchmarkResult.ScrollBars = ScrollBars.Vertical;
        _txtBenchmarkResult.Font = new System.Drawing.Font("Consolas", 9F);
        benchBox.Controls.Add(_txtBenchmarkResult);
        flow.Controls.Add(benchBox);

        page.Controls.Add(flow);
        return page;
    }

    private void GenerateKeyPair_Click(object? sender, EventArgs e)
    {
        try
        {
            int keySize = _cmbKeySize.SelectedIndex switch { 1 => 3072, 2 => 4096, _ => 2048 };
            RSA newPrivate = RsaKeyService.CreateKeyPair(keySize);
            RSA newPublic = RsaKeyService.CreatePublicOnly(newPrivate);
            ReplaceKey(ref _privateRsa, newPrivate);
            ReplaceKey(ref _publicRsa, newPublic);
            _txtPemInput.Text = RsaKeyService.ExportPrivatePem(_privateRsa);
            _txtPemAnalysis.Text = "Đã tạo cặp khóa RSA. PEM khóa bí mật đang được hiển thị ở ô bên trái.\r\n\r\n" +
                RsaKeyService.AnalyzePem(_txtPemInput.Text);
            RefreshKeyStatus();
            ShowInfo($"Đã sinh cặp khóa RSA-{keySize} bit.");
        }
        catch (Exception ex) { ShowError("Không thể tạo cặp khóa: " + GetFriendlyError(ex)); }
    }

    private void ExportPublicKey()
    {
        if (_publicRsa is null) { ShowError("Chưa có khóa công khai. Hãy tạo cặp khóa hoặc nhập PEM khóa công khai trước."); return; }
        using SaveFileDialog dialog = new() { Title = "Lưu PEM khóa công khai", Filter = "Tệp PEM (*.pem)|*.pem|Tất cả tệp (*.*)|*.*", FileName = "khoa_cong_khai.pem" };
        if (dialog.ShowDialog(this) != DialogResult.OK) return;
        try
        {
            File.WriteAllText(dialog.FileName, RsaKeyService.ExportPublicPem(_publicRsa), new UTF8Encoding(false));
            ShowInfo("Đã xuất PEM khóa công khai thành công.");
        }
        catch (Exception ex) { ShowError("Không thể xuất khóa công khai: " + GetFriendlyError(ex)); }
    }

    private void ExportPrivateKey()
    {
        if (_privateRsa is null) { ShowError("Chưa có khóa bí mật. Hãy tạo cặp khóa hoặc nhập PEM khóa bí mật trước."); return; }
        using SaveFileDialog dialog = new() { Title = "Lưu PEM khóa bí mật", Filter = "Tệp PEM (*.pem)|*.pem|Tất cả tệp (*.*)|*.*", FileName = "khoa_bi_mat.pem" };
        if (dialog.ShowDialog(this) != DialogResult.OK) return;
        try
        {
            File.WriteAllText(dialog.FileName, RsaKeyService.ExportPrivatePem(_privateRsa), new UTF8Encoding(false));
            ShowInfo("Đã xuất PEM khóa bí mật. Hãy giữ tệp này an toàn và bí mật.");
        }
        catch (Exception ex) { ShowError("Không thể xuất khóa bí mật: " + GetFriendlyError(ex)); }
    }

    private void ImportPublicFromFile()
    {
        using OpenFileDialog dialog = new() { Title = "Chọn PEM khóa công khai", Filter = "Tệp PEM (*.pem;*.txt)|*.pem;*.txt|Tất cả tệp (*.*)|*.*" };
        if (dialog.ShowDialog(this) != DialogResult.OK) return;
        try
        {
            string pem = File.ReadAllText(dialog.FileName);
            RSA rsa = RsaKeyService.ImportPublicPem(pem);
            ReplaceKey(ref _publicRsa, rsa);
            _txtPemInput.Text = pem;
            _txtPemAnalysis.Text = RsaKeyService.AnalyzePem(pem);
            RefreshKeyStatus();
            ShowInfo("Đã nhập khóa công khai thành công.");
        }
        catch (Exception ex) { ShowError("Nhập khóa công khai thất bại: " + GetFriendlyError(ex)); }
    }

    private void ImportPrivateFromFile()
    {
        using OpenFileDialog dialog = new() { Title = "Chọn PEM khóa bí mật", Filter = "Tệp PEM (*.pem;*.txt)|*.pem;*.txt|Tất cả tệp (*.*)|*.*" };
        if (dialog.ShowDialog(this) != DialogResult.OK) return;
        try
        {
            string pem = File.ReadAllText(dialog.FileName);
            RSA rsa = RsaKeyService.ImportPrivatePem(pem);
            ReplaceKey(ref _privateRsa, rsa);
            _txtPemInput.Text = pem;
            _txtPemAnalysis.Text = RsaKeyService.AnalyzePem(pem);
            RefreshKeyStatus();
            ShowInfo("Đã nhập khóa bí mật thành công. Hãy bảo vệ tệp PEM khóa bí mật.");
        }
        catch (Exception ex) { ShowError("Nhập khóa bí mật thất bại: " + GetFriendlyError(ex)); }
    }

    private void LoadPemTextFromFile()
    {
        using OpenFileDialog dialog = new() { Title = "Mở tệp PEM", Filter = "Tệp PEM (*.pem;*.txt)|*.pem;*.txt|Tất cả tệp (*.*)|*.*" };
        if (dialog.ShowDialog(this) != DialogResult.OK) return;
        try { _txtPemInput.Text = File.ReadAllText(dialog.FileName); }
        catch (Exception ex) { ShowError("Không thể đọc tệp PEM: " + GetFriendlyError(ex)); }
    }

    private void AnalyzePemText()
    {
        try { _txtPemAnalysis.Text = RsaKeyService.AnalyzePem(_txtPemInput.Text); }
        catch (Exception ex) { ShowError("Phân tích PEM thất bại: " + GetFriendlyError(ex)); }
    }

    private void ImportPublicFromText()
    {
        try
        {
            RSA rsa = RsaKeyService.ImportPublicPem(_txtPemInput.Text);
            ReplaceKey(ref _publicRsa, rsa);
            _txtPemAnalysis.Text = RsaKeyService.AnalyzePem(_txtPemInput.Text);
            RefreshKeyStatus();
            ShowInfo("Đã nhập khóa công khai từ nội dung PEM.");
        }
        catch (Exception ex) { ShowError("Nhập khóa công khai thất bại: " + GetFriendlyError(ex)); }
    }

    private void ImportPrivateFromText()
    {
        try
        {
            RSA rsa = RsaKeyService.ImportPrivatePem(_txtPemInput.Text);
            ReplaceKey(ref _privateRsa, rsa);
            _txtPemAnalysis.Text = RsaKeyService.AnalyzePem(_txtPemInput.Text);
            RefreshKeyStatus();
            ShowInfo("Đã nhập khóa bí mật từ nội dung PEM.");
        }
        catch (Exception ex) { ShowError("Nhập khóa bí mật thất bại: " + GetFriendlyError(ex)); }
    }

    private void RefreshKeyStatus()
    {
        _lblPublicStatus.Text = _publicRsa is null ? "Khóa công khai: chưa có" : $"Khóa công khai: đã nạp RSA-{_publicRsa.KeySize} bit";
        _lblPrivateStatus.Text = _privateRsa is null ? "Khóa bí mật: chưa có" : $"Khóa bí mật: đã nạp RSA-{_privateRsa.KeySize} bit";
        _lblPrivateStatus.ForeColor = System.Drawing.Color.Black;

        if (_publicRsa is not null && _privateRsa is not null)
        {
            bool matchingPair = AreCurrentKeysAPair();
            _lblPrivateStatus.Text += matchingPair
                ? " | Cặp khóa khớp"
                : " | CẢNH BÁO: hai khóa không cùng cặp";
            _lblPrivateStatus.ForeColor = matchingPair
                ? System.Drawing.Color.DarkGreen
                : System.Drawing.Color.DarkRed;
        }

        if (_privateRsa is not null)
            _txtKeyDetails.Text = RsaKeyService.DescribeParameters(_privateRsa, true);
        else if (_publicRsa is not null)
            _txtKeyDetails.Text = RsaKeyService.DescribeParameters(_publicRsa, false);
        else
            _txtKeyDetails.Text = "Chưa nạp khóa nào.";

        // Đồng bộ giới hạn byte hiển thị khi nạp hoặc thay đổi khóa RSA.
        UpdateInputByteCount();
        UpdateByteArrayBase64Count();
    }

    private bool AreCurrentKeysAPair()
    {
        if (_publicRsa is null || _privateRsa is null)
            return false;

        try
        {
            // Thử thách ngẫu nhiên 32 byte chỉ dùng nội bộ để kiểm tra hai khóa có khớp hay không.
            byte[] challenge = RandomNumberGenerator.GetBytes(32);
            byte[] cipher = _publicRsa.Encrypt(challenge, RSAEncryptionPadding.OaepSHA256);
            byte[] recovered = _privateRsa.Decrypt(cipher, RSAEncryptionPadding.OaepSHA256);
            return CryptographicOperations.FixedTimeEquals(challenge, recovered);
        }
        catch (CryptographicException)
        {
            return false;
        }
        catch (ArgumentException)
        {
            return false;
        }
    }

    private void UpdateInputByteCount()
    {
        int count = Encoding.UTF8.GetByteCount(_txtPlainText.Text);
        int limit = _publicRsa is null ? RsaCryptoService.AssignmentMaximumBytes : RsaCryptoService.GetMaximumInputBytes(_publicRsa);
        _lblInputByteCount.Text = $"Độ dài dữ liệu: {count} byte UTF-8. Giới hạn bài tập: tối đa {limit} byte. (Cần khóa công khai để mã hóa.)";
        _lblInputByteCount.ForeColor = count <= limit ? System.Drawing.Color.DarkGreen : System.Drawing.Color.DarkRed;
    }

    private void UpdateByteArrayBase64Count()
    {
        if (string.IsNullOrWhiteSpace(_txtByteArrayBase64.Text))
        {
            _lblByteArrayBase64Count.Text = "Số byte: 0";
            _lblByteArrayBase64Count.ForeColor = System.Drawing.Color.Black;
            return;
        }

        try
        {
            byte[] bytes = Convert.FromBase64String(_txtByteArrayBase64.Text.Trim());
            int limit = _publicRsa is null
                ? RsaCryptoService.AssignmentMaximumBytes
                : RsaCryptoService.GetMaximumInputBytes(_publicRsa);
            _lblByteArrayBase64Count.Text = $"Hợp lệ: {bytes.Length} / {limit} byte";
            _lblByteArrayBase64Count.ForeColor = bytes.Length <= limit
                ? System.Drawing.Color.DarkGreen
                : System.Drawing.Color.DarkRed;
        }
        catch (FormatException)
        {
            _lblByteArrayBase64Count.Text = "Base64 chưa hợp lệ";
            _lblByteArrayBase64Count.ForeColor = System.Drawing.Color.DarkRed;
        }
    }

    private void EncryptByteArrayBase64()
    {
        try
        {
            if (_publicRsa is null)
            {
                ShowError("Chưa có khóa công khai. Hãy tạo cặp khóa hoặc nhập PEM khóa công khai.");
                return;
            }
            if (string.IsNullOrWhiteSpace(_txtByteArrayBase64.Text))
            {
                ShowError("Hãy nhập mảng byte nguồn dưới dạng Base64.");
                return;
            }

            byte[] data = Convert.FromBase64String(_txtByteArrayBase64.Text.Trim());
            byte[] cipher = RsaCryptoService.Encrypt(data, _publicRsa);
            _lastPlainData = data.ToArray();
            _lastDecryptedData = null;
            _txtCipherBase64.Text = Convert.ToBase64String(cipher);
            _lblDataCompare.Text = $"Đã mã hóa mảng byte Base64: {data.Length} byte.";
            _lblDataCompare.ForeColor = System.Drawing.Color.DarkGreen;
            ShowInfo($"Mã hóa thành công mảng byte Base64. Dữ liệu nguồn: {data.Length} byte; bản mã: {cipher.Length} byte.");
        }
        catch (Exception ex)
        {
            ShowError("Mã hóa mảng byte Base64 thất bại: " + GetFriendlyError(ex));
        }
    }

    private void EncryptTextData()
    {
        try
        {
            if (_publicRsa is null) { ShowError("Chưa có khóa công khai. Hãy tạo cặp khóa hoặc nhập PEM khóa công khai."); return; }
            byte[] data = Encoding.UTF8.GetBytes(_txtPlainText.Text);
            byte[] cipher = RsaCryptoService.Encrypt(data, _publicRsa);
            _lastPlainData = data.ToArray();
            _lastDecryptedData = null;
            _txtCipherBase64.Text = Convert.ToBase64String(cipher);
            _lblDataCompare.Text = "Đã mã hóa. Hãy giải mã bằng khóa bí mật để đối chiếu.";
            ShowInfo($"Mã hóa thành công. Dữ liệu nguồn: {data.Length} byte; bản mã: {cipher.Length} byte.");
        }
        catch (Exception ex) { ShowError("Mã hóa thất bại: " + GetFriendlyError(ex)); }
    }

    private void CreateAesDemoKey()
    {
        if (_demoAesKey is not null)
            CryptographicOperations.ZeroMemory(_demoAesKey);
        _demoAesKey = RandomNumberGenerator.GetBytes(32);
        _lblAesSample.Text = "Đã tạo khóa AES-256 mẫu 32 byte. Biểu diễn Base64: " + Convert.ToBase64String(_demoAesKey);
    }

    private void EncryptAesDemoKey()
    {
        try
        {
            if (_publicRsa is null) { ShowError("Chưa có khóa công khai. Hãy tạo cặp khóa hoặc nhập PEM khóa công khai."); return; }
            if (_demoAesKey is null) { ShowError("Hãy tạo khóa AES-256 mẫu trước."); return; }
            byte[] cipher = RsaCryptoService.Encrypt(_demoAesKey, _publicRsa);
            _lastPlainData = _demoAesKey.ToArray();
            _lastDecryptedData = null;
            _txtCipherBase64.Text = Convert.ToBase64String(cipher);
            _lblDataCompare.Text = "Đã mã hóa mảng byte khóa AES-256 (32 byte).";
            ShowInfo($"Mã hóa khóa AES mẫu thành công: 32 byte đầu vào, {cipher.Length} byte bản mã.");
        }
        catch (Exception ex) { ShowError("Mã hóa khóa AES thất bại: " + GetFriendlyError(ex)); }
    }

    private void SaveCiphertextToFile()
    {
        if (string.IsNullOrWhiteSpace(_txtCipherBase64.Text)) { ShowError("Chưa có bản mã Base64 để lưu."); return; }
        using SaveFileDialog dialog = new() { Title = "Lưu bản mã Base64", Filter = "Tệp Base64 (*.b64)|*.b64|Tệp văn bản (*.txt)|*.txt|Tất cả tệp (*.*)|*.*", FileName = "ban_ma_rsa.b64" };
        if (dialog.ShowDialog(this) != DialogResult.OK) return;
        try
        {
            byte[] check = Convert.FromBase64String(_txtCipherBase64.Text.Trim());
            File.WriteAllText(dialog.FileName, Convert.ToBase64String(check), Encoding.ASCII);
            ShowInfo("Đã lưu bản mã Base64 ra tệp.");
        }
        catch (Exception ex) { ShowError("Không thể lưu bản mã: " + GetFriendlyError(ex)); }
    }

    private void DecryptCiphertextFromFile()
    {
        using OpenFileDialog dialog = new() { Title = "Chọn tệp bản mã Base64", Filter = "Tệp Base64 (*.b64;*.txt)|*.b64;*.txt|Tất cả tệp (*.*)|*.*" };
        if (dialog.ShowDialog(this) != DialogResult.OK) return;
        try
        {
            // Bản mã được đọc từ tệp có thể thuộc một phiên làm việc trước; không dùng nhầm nguồn cũ trong RAM.
            _lastPlainData = null;
            _lastDecryptedData = null;
            _txtDecryptedBase64.Clear();
            _txtDecryptedText.Clear();
            _txtCipherBase64.Text = File.ReadAllText(dialog.FileName).Trim();
            DecryptCurrentCiphertext();
        }
        catch (Exception ex) { ShowError("Không thể đọc tệp bản mã: " + GetFriendlyError(ex)); }
    }

    private void DecryptCurrentCiphertext()
    {
        try
        {
            if (_privateRsa is null) { ShowError("Chưa có khóa bí mật. Hãy tạo cặp khóa hoặc nhập PEM khóa bí mật."); return; }
            if (string.IsNullOrWhiteSpace(_txtCipherBase64.Text)) { ShowError("Hãy dán bản mã Base64 hoặc đọc từ tệp."); return; }
            byte[] cipher = Convert.FromBase64String(_txtCipherBase64.Text.Trim());
            byte[] plain = RsaCryptoService.Decrypt(cipher, _privateRsa);
            _lastDecryptedData = plain;
            _txtDecryptedBase64.Text = Convert.ToBase64String(plain);
            try
            {
                _txtDecryptedText.Text = new UTF8Encoding(false, true).GetString(plain);
            }
            catch (DecoderFallbackException)
            {
                _txtDecryptedText.Text = "Dữ liệu giải mã là mảng byte nhị phân, không phải UTF-8 hợp lệ.";
            }

            if (_lastPlainData is not null)
            {
                bool equal = _lastPlainData.SequenceEqual(plain);
                _lblDataCompare.Text = equal
                    ? $"KẾT QUẢ: GIỐNG HỆT ({plain.Length} byte)."
                    : "KẾT QUẢ: KHÁC DỮ LIỆU NGUỒN đã lưu trong phiên làm việc.";
                _lblDataCompare.ForeColor = equal ? System.Drawing.Color.DarkGreen : System.Drawing.Color.DarkRed;
            }
            else
            {
                _lblDataCompare.Text = "Đã giải mã; chưa có dữ liệu nguồn trong phiên này để đối chiếu.";
                _lblDataCompare.ForeColor = System.Drawing.Color.Black;
            }
            ShowInfo($"Giải mã thành công. Đã thu được {plain.Length} byte.");
        }
        catch (Exception ex) { ShowError("Giải mã thất bại. Hãy kiểm tra khóa bí mật, tệp Base64 và cặp khóa. Chi tiết: " + GetFriendlyError(ex)); }
    }

    private void CompareCurrentData()
    {
        if (_lastDecryptedData is null)
        {
            ShowError("Chưa có dữ liệu giải mã để so sánh. Hãy giải mã bản mã trước.");
            return;
        }

        // Ưu tiên mảng nguồn đã dùng để mã hóa trong phiên hiện tại.
        // Nếu đang kiểm tra tệp cũ, cho phép so sánh với Base64 byte[] hoặc văn bản UTF-8 đang nhập.
        byte[] source;
        string sourceDescription;
        if (_lastPlainData is not null)
        {
            source = _lastPlainData;
            sourceDescription = "mảng byte nguồn đã lưu trong phiên làm việc";
        }
        else if (!string.IsNullOrWhiteSpace(_txtByteArrayBase64.Text))
        {
            try
            {
                source = Convert.FromBase64String(_txtByteArrayBase64.Text.Trim());
                sourceDescription = "mảng byte Base64 đang nhập";
            }
            catch (FormatException)
            {
                ShowError("Dữ liệu nguồn Base64 chưa hợp lệ. Hãy sửa Base64 hoặc xóa ô này để so sánh văn bản UTF-8.");
                return;
            }
        }
        else
        {
            source = Encoding.UTF8.GetBytes(_txtPlainText.Text);
            sourceDescription = "văn bản UTF-8 đang có trong ô dữ liệu nguồn";
        }

        bool equal = source.SequenceEqual(_lastDecryptedData);
        _lblDataCompare.Text = equal
            ? $"GIỐNG HỆT: {source.Length} byte nguồn khớp hoàn toàn với dữ liệu giải mã."
            : $"KHÁC NHAU: dữ liệu giải mã không trùng với {sourceDescription}.";
        _lblDataCompare.ForeColor = equal ? System.Drawing.Color.DarkGreen : System.Drawing.Color.DarkRed;
    }

    private void SaveDecryptedData()
    {
        if (_lastDecryptedData is null) { ShowError("Chưa có dữ liệu giải mã để lưu."); return; }
        using SaveFileDialog dialog = new() { Title = "Lưu mảng byte đã giải mã", Filter = "Tệp nhị phân (*.bin)|*.bin|Tất cả tệp (*.*)|*.*", FileName = "du_lieu_giai_ma.bin" };
        if (dialog.ShowDialog(this) != DialogResult.OK) return;
        try
        {
            File.WriteAllBytes(dialog.FileName, _lastDecryptedData);
            ShowInfo("Đã lưu dữ liệu giải mã dạng byte ra tệp.");
        }
        catch (Exception ex) { ShowError("Không thể lưu dữ liệu giải mã: " + GetFriendlyError(ex)); }
    }

    private void UpdateHashes()
    {
        byte[] a = HashService.ComputeSha256(Encoding.UTF8.GetBytes(_txtHashA.Text));
        byte[] b = HashService.ComputeSha256(Encoding.UTF8.GetBytes(_txtHashB.Text));
        _txtHashOutA.Text = Convert.ToHexString(a);
        _txtHashOutB.Text = Convert.ToHexString(b);
        int different = HashService.CountDifferentBits(a, b);
        _lblHashDifference.Text = $"Số bit khác nhau: {different}/256 ({different / 256.0:P2}).";
    }

    private void SignCurrentData()
    {
        try
        {
            if (_privateRsa is null) { ShowError("Chưa có khóa bí mật để ký. Hãy tạo cặp khóa hoặc nhập PEM khóa bí mật."); return; }
            byte[] data = Encoding.UTF8.GetBytes(_txtSignData.Text);
            byte[] signature = RsaCryptoService.Sign(data, _privateRsa);
            string keyFingerprint = Convert.ToHexString(SHA256.HashData(_privateRsa.ExportSubjectPublicKeyInfo()));
            bool repeatedSameData = _lastSignedData is not null && _lastSignedData.SequenceEqual(data);
            bool sameSigningKey = _lastSigningKeyFingerprint is not null &&
                                  string.Equals(_lastSigningKeyFingerprint, keyFingerprint, StringComparison.Ordinal);
            bool repeatedSameDataAndKey = repeatedSameData && sameSigningKey;
            bool signatureDiffers = _lastSignature is not null && !_lastSignature.SequenceEqual(signature);
            _txtSignature.Text = Convert.ToBase64String(signature);

            if (repeatedSameDataAndKey && signatureDiffers)
            {
                _lblSignatureStatus.Text = "THÀNH CÔNG: cùng dữ liệu và cùng khóa bí mật, chữ ký mới khác chữ ký trước (RSA-PSS).";
                _lblSignatureStatus.ForeColor = System.Drawing.Color.DarkGreen;
            }
            else if (repeatedSameDataAndKey)
            {
                _lblSignatureStatus.Text = "Chữ ký trùng với lần trước. Đây là trường hợp rất hiếm; hãy ký lại để thử tiếp.";
                _lblSignatureStatus.ForeColor = System.Drawing.Color.DarkOrange;
            }
            else if (repeatedSameData && !sameSigningKey)
            {
                _lblSignatureStatus.Text = "Dữ liệu giống lần trước nhưng khóa bí mật đã thay đổi; hãy ký lại với cùng khóa để kiểm tra tính ngẫu nhiên.";
                _lblSignatureStatus.ForeColor = System.Drawing.Color.DarkOrange;
            }
            else
            {
                _lblSignatureStatus.Text = "Đã tạo chữ ký. Bấm Ký lần nữa với đúng dữ liệu và cùng khóa để kiểm tra tính ngẫu nhiên của chữ ký.";
                _lblSignatureStatus.ForeColor = System.Drawing.Color.Black;
            }
            _lastSignedData = data.ToArray();
            _lastSignature = signature.ToArray();
            _lastSigningKeyFingerprint = keyFingerprint;
        }
        catch (Exception ex) { ShowError("Tạo chữ ký thất bại: " + GetFriendlyError(ex)); }
    }

    private void SaveSignatureToFile()
    {
        if (string.IsNullOrWhiteSpace(_txtSignature.Text)) { ShowError("Chưa có chữ ký để lưu."); return; }
        using SaveFileDialog dialog = new() { Title = "Lưu chữ ký Base64", Filter = "Tệp chữ ký Base64 (*.sig.b64)|*.sig.b64|Tệp văn bản (*.txt)|*.txt|Tất cả tệp (*.*)|*.*", FileName = "chu_ky_so.sig.b64" };
        if (dialog.ShowDialog(this) != DialogResult.OK) return;
        try
        {
            byte[] signature = Convert.FromBase64String(_txtSignature.Text.Trim());
            File.WriteAllText(dialog.FileName, Convert.ToBase64String(signature), Encoding.ASCII);
            ShowInfo("Đã lưu chữ ký Base64 ra tệp.");
        }
        catch (Exception ex) { ShowError("Không thể lưu chữ ký: " + GetFriendlyError(ex)); }
    }

    private void VerifyCurrentSignature()
    {
        try
        {
            if (_publicRsa is null) { ShowError("Chưa có khóa công khai để xác minh."); return; }
            if (string.IsNullOrWhiteSpace(_txtSignature.Text)) { ShowError("Hãy dán chữ ký Base64 vào ô chữ ký."); return; }
            byte[] data = Encoding.UTF8.GetBytes(_txtSignData.Text);
            byte[] signature = Convert.FromBase64String(_txtSignature.Text.Trim());
            bool valid = RsaCryptoService.VerifySignature(data, signature, _publicRsa);
            _lblSignatureStatus.Text = valid ? "CHỮ KÝ HỢP LỆ: chữ ký khớp với dữ liệu và khóa công khai." : "CHỮ KÝ KHÔNG HỢP LỆ: dữ liệu có thể đã thay đổi hoặc khóa công khai không đúng.";
            _lblSignatureStatus.ForeColor = valid ? System.Drawing.Color.DarkGreen : System.Drawing.Color.DarkRed;
        }
        catch (Exception ex)
        {
            _lblSignatureStatus.Text = "Không thể xác minh chữ ký: " + GetFriendlyError(ex);
            _lblSignatureStatus.ForeColor = System.Drawing.Color.DarkRed;
        }
    }

    private void RunBenchmark()
    {
        try
        {
            if (_publicRsa is null || _privateRsa is null)
            {
                ShowError("Cần cả khóa công khai và khóa bí mật để đo đủ cả bốn phép toán.");
                return;
            }
            byte[] data = Encoding.UTF8.GetBytes(_txtBenchmarkData.Text);
            int limit = Math.Min(RsaCryptoService.GetMaximumInputBytes(_publicRsa), RsaCryptoService.GetMaximumInputBytes(_privateRsa));
            if (data.Length > limit)
            {
                ShowError($"Dữ liệu đo tốc độ có {data.Length} byte; giới hạn là {limit} byte.");
                return;
            }
            int iterations = (int)_numIterations.Value;
            byte[] checkCipher = RsaCryptoService.Encrypt(data, _publicRsa);
            byte[] checkPlain = RsaCryptoService.Decrypt(checkCipher, _privateRsa);
            if (!data.SequenceEqual(checkPlain))
                throw new CryptographicException("Khóa công khai và khóa bí mật không phải một cặp tương ứng.");
            byte[] checkSignature = RsaCryptoService.Sign(data, _privateRsa);
            if (!RsaCryptoService.VerifySignature(data, checkSignature, _publicRsa))
                throw new CryptographicException("Khóa công khai và khóa bí mật không xác minh được cùng một cặp.");

            // Làm nóng các đường thực thi trước khi đo để giảm ảnh hưởng khởi tạo/JIT.
            int warmupIterations = Math.Min(5, iterations);
            for (int i = 0; i < warmupIterations; i++)
            {
                _ = RsaCryptoService.Encrypt(data, _publicRsa);
                _ = RsaCryptoService.Decrypt(checkCipher, _privateRsa);
                _ = RsaCryptoService.Sign(data, _privateRsa);
                _ = RsaCryptoService.VerifySignature(data, checkSignature, _publicRsa);
            }

            Stopwatch sw = Stopwatch.StartNew();
            for (int i = 0; i < iterations; i++) _ = RsaCryptoService.Encrypt(data, _publicRsa);
            sw.Stop();
            TimeSpan encryptElapsed = sw.Elapsed;

            sw.Restart();
            for (int i = 0; i < iterations; i++) _ = RsaCryptoService.Decrypt(checkCipher, _privateRsa);
            sw.Stop();
            TimeSpan decryptElapsed = sw.Elapsed;

            sw.Restart();
            for (int i = 0; i < iterations; i++) _ = RsaCryptoService.Sign(data, _privateRsa);
            sw.Stop();
            TimeSpan signElapsed = sw.Elapsed;

            sw.Restart();
            for (int i = 0; i < iterations; i++)
            {
                if (!RsaCryptoService.VerifySignature(data, checkSignature, _publicRsa))
                    throw new CryptographicException("Phép xác minh chữ ký thất bại trong lúc đo tốc độ.");
            }
            sw.Stop();
            TimeSpan verifyElapsed = sw.Elapsed;

            StringBuilder sb = new();
            sb.AppendLine($"Kích thước khóa công khai/bí mật: {_publicRsa.KeySize}/{_privateRsa.KeySize} bit");
            sb.AppendLine($"Dữ liệu: {data.Length} byte; số lần lặp: {iterations}");
            sb.AppendLine(FormatBenchmarkLine("Mã hóa (khóa công khai)", encryptElapsed, iterations));
            sb.AppendLine(FormatBenchmarkLine("Giải mã (khóa bí mật)", decryptElapsed, iterations));
            sb.AppendLine(FormatBenchmarkLine("Ký RSA-PSS (khóa bí mật)", signElapsed, iterations));
            sb.AppendLine(FormatBenchmarkLine("Xác minh (khóa công khai)", verifyElapsed, iterations));
            sb.AppendLine();
            sb.AppendLine($"Đã làm nóng trước {warmupIterations} lượt cho mỗi phép toán; các lượt này không tính vào thời gian đo.");
            sb.AppendLine("Nhận xét: đây là kết quả trên máy hiện tại; thời gian phụ thuộc CPU, thư viện và số lần lặp.");
            sb.AppendLine("Thông thường, phép toán khóa bí mật (d) chậm hơn phép toán khóa công khai (e), nhưng hãy đưa ra kết luận theo số liệu đo được.");
            _txtBenchmarkResult.Text = sb.ToString();
        }
        catch (Exception ex) { ShowError("Đo tốc độ thất bại: " + GetFriendlyError(ex)); }
    }

    private static string FormatBenchmarkLine(string title, TimeSpan elapsed, int iterations)
    {
        double totalMs = elapsed.TotalMilliseconds;
        double averageMs = totalMs / iterations;
        double opsPerSecond = elapsed.TotalSeconds <= 0 ? 0 : iterations / elapsed.TotalSeconds;
        return $"{title,-28} Tổng: {totalMs,10:F3} ms | Trung bình: {averageMs,9:F4} ms/lần | Tốc độ: {opsPerSecond,10:F2} lần/giây";
    }

    private static void ReplaceKey(ref RSA? target, RSA newKey)
    {
        target?.Dispose();
        target = newKey;
    }

    private static FlowLayoutPanel CreateFlowPanel()
    {
        return new FlowLayoutPanel
        {
            Dock = DockStyle.Fill,
            AutoScroll = true,
            FlowDirection = FlowDirection.TopDown,
            WrapContents = false,
            Padding = new Padding(10)
        };
    }

    private static GroupBox CreateGroup(string title, int width, int height)
    {
        return new GroupBox
        {
            Text = title,
            Width = width,
            Height = height,
            Margin = new Padding(5, 5, 5, 12),
            Padding = new Padding(8)
        };
    }

    private static void AddLabel(Control parent, string text, int x, int y, int width, int height)
    {
        Label label = new()
        {
            Text = text,
            Left = x,
            Top = y,
            Width = width,
            Height = height,
            AutoEllipsis = false
        };
        parent.Controls.Add(label);
    }

    private static Button MakeButton(string text, int x, int y, int width, int height, EventHandler click)
    {
        Button button = new() { Text = text, Left = x, Top = y, Width = width, Height = height };
        button.Click += click;
        return button;
    }

    private static string GetFriendlyError(Exception ex)
    {
        return ex switch
        {
            CryptographicException => "Thao tác mật mã thất bại. Hãy kiểm tra khóa, dữ liệu và định dạng.",
            FormatException => "Dữ liệu không đúng định dạng. Hãy kiểm tra PEM hoặc Base64.",
            UnauthorizedAccessException => "Không có quyền truy cập tệp đã chọn.",
            IOException => "Không thể đọc hoặc ghi tệp. Hãy kiểm tra đường dẫn và quyền truy cập.",
            ArgumentException => "Dữ liệu đầu vào không hợp lệ. Hãy kiểm tra độ dài và định dạng.",
            _ => "Đã xảy ra lỗi ngoài dự kiến. Hãy kiểm tra lại thao tác và dữ liệu đầu vào."
        };
    }

    private void ShowInfo(string message) => MessageBox.Show(this, message, "Thông báo", MessageBoxButtons.OK, MessageBoxIcon.Information);

    private void ShowError(string message) => MessageBox.Show(this, message, "Lỗi", MessageBoxButtons.OK, MessageBoxIcon.Error);

    protected override void OnFormClosed(FormClosedEventArgs e)
    {
        _publicRsa?.Dispose();
        _privateRsa?.Dispose();
        if (_demoAesKey is not null)
            CryptographicOperations.ZeroMemory(_demoAesKey);
        base.OnFormClosed(e);
    }
}
