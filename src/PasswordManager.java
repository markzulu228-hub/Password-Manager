import javax.crypto.AEADBadTagException;
import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import javax.imageio.ImageIO;
import javax.swing.*;
import javax.swing.border.EmptyBorder;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;
import javax.swing.plaf.basic.BasicScrollBarUI;
import javax.swing.table.AbstractTableModel;
import javax.swing.table.DefaultTableCellRenderer;
import javax.swing.table.JTableHeader;
import javax.swing.table.TableRowSorter;
import javax.swing.text.JTextComponent;
import java.awt.*;
import java.awt.datatransfer.Clipboard;
import java.awt.datatransfer.DataFlavor;
import java.awt.datatransfer.StringSelection;
import java.awt.event.AWTEventListener;
import java.awt.event.ActionEvent;
import java.awt.event.FocusAdapter;
import java.awt.event.FocusEvent;
import java.awt.event.KeyEvent;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.awt.image.BufferedImage;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.nio.file.AtomicMoveNotSupportedException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardCopyOption;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.UUID;
import java.util.function.Supplier;
import java.util.regex.Pattern;

/**
 * Encrypted desktop password manager with a modern dark UI.
 *
 * Security:   AES-256-GCM vault, PBKDF2-HMAC-SHA256 key derivation, change master
 *             password, escalating unlock delay, auto-lock, clipboard auto-clear,
 *             security audit, Have I Been Pwned breach check (k-anonymity).
 * Productivity: search, categories, website links, 2FA (TOTP) codes, password
 *             history, CSV import/export, undo delete, auto-backup, settings,
 *             keyboard shortcuts (Ctrl+N add, Ctrl+F search, Ctrl+L lock, Ctrl+Z undo).
 *
 * Connectivity: auto-type into other apps (Tools: Ctrl+T), cloud-folder sync with automatic
 *             merging of changes made on different computers (Tools > Vault location).
 *
 * Run:  javac PasswordManager.java  &&  java PasswordManager
 */
public class PasswordManager {

    static final Path CONFIG_PATH = Paths.get(System.getProperty("user.home"), ".password-manager.properties");
    /** Where the vault lives. It can be moved into a cloud-synced folder (Tools > Vault location). */
    static Path vaultPath = loadVaultPath();
    static final long TOMBSTONE_KEEP_MS = 180L * 86_400_000L;
    static final int SYNC_CHECK_MS = 10_000;
    static final int MIN_MASTER_LENGTH = 10;
    static final int MAX_HISTORY = 10;
    static final int OLD_PASSWORD_DAYS = 180;
    static final SecureRandom RNG = new SecureRandom();
    static final String MASK = "\u2022\u2022\u2022\u2022\u2022\u2022\u2022\u2022";

    // Unlock throttling (in memory; deters casual guessing at the prompt)
    static int failedAttempts;
    static long lockedUntil;

    // ---- Theme -------------------------------------------------------
    static final Color BG = new Color(0x12151A);
    static final Color PANEL = new Color(0x1A1E25);
    static final Color ROW_ALT = new Color(0x1E232B);
    static final Color CARD = new Color(0x242A34);
    static final Color FIELD = new Color(0x151920);
    static final Color BORDER = new Color(0x333B49);
    static final Color TEXT = new Color(0xE7EAF0);
    static final Color MUTED = new Color(0x8C95A6);
    static final Color ACCENT = new Color(0x4C8DFF);
    static final Color ACCENT_2 = new Color(0x7A5CFF);
    static final Color DANGER = new Color(0xE5534B);
    static final Color GOOD = new Color(0x3FB950);
    static final Color WARN = new Color(0xD9A227);
    static final Color SELECT = new Color(0x27487D);
    static final Color[] AVATARS = {
            new Color(0x4C8DFF), new Color(0x7A5CFF), new Color(0x1F9D8B),
            new Color(0xD9822B), new Color(0xC2477F), new Color(0x3E9B4F)};

    static Path loadVaultPath() {
        try {
            if (Files.exists(CONFIG_PATH)) {
                Properties props = new Properties();
                try (java.io.Reader r = Files.newBufferedReader(CONFIG_PATH, StandardCharsets.UTF_8)) {
                    props.load(r);
                }
                String v = props.getProperty("vault.path");
                if (v != null && !v.trim().isEmpty()) {
                    return Paths.get(v.trim());
                }
            }
        } catch (Exception ignored) {
            // fall back to the default location
        }
        Path def = defaultVaultPath(System.getProperty("os.name", ""), System.getenv("APPDATA"),
                System.getenv("XDG_DATA_HOME"), System.getProperty("user.home"));
        // keep using a vault.dat from an older version that sits next to where the app was started
        Path legacy = Paths.get("vault.dat").toAbsolutePath();
        if (!Files.exists(def) && Files.exists(legacy)) {
            return legacy;
        }
        return def;
    }

    /** Per-user data folder for each OS, so an installed app never writes into its own folder. */
    static Path defaultVaultPath(String osName, String appData, String xdgData, String home) {
        String os = osName.toLowerCase();
        Path dir;
        if (os.contains("mac")) {
            dir = Paths.get(home, "Library", "Application Support", "PasswordManager");
        } else if (os.contains("win")) {
            String base = appData != null && !appData.isEmpty() ? appData : Paths.get(home, "AppData", "Roaming").toString();
            dir = Paths.get(base, "PasswordManager");
        } else {
            String base = xdgData != null && !xdgData.isEmpty() ? xdgData : Paths.get(home, ".local", "share").toString();
            dir = Paths.get(base, "password-manager");
        }
        return dir.resolve("vault.dat");
    }

    static void saveVaultPath(Path p) throws IOException {
        Properties props = new Properties();
        props.setProperty("vault.path", p.toAbsolutePath().toString());
        try (java.io.Writer w = Files.newBufferedWriter(CONFIG_PATH, StandardCharsets.UTF_8)) {
            props.store(w, "Password Manager: vault location");
        }
    }

    static Font font(int style, float size) {
        return new Font("SansSerif", Font.PLAIN, 12).deriveFont(style, size);
    }

    public static void main(String[] args) {
        if (args.length >= 2 && args[0].equals("--write-icons")) {
            // build helper: writes icon.png, icon.ico and icon.icns for the installers
            System.setProperty("java.awt.headless", "true");
            try {
                writeIcons(Paths.get(args[1]));
                System.out.println("Icons written to " + args[1]);
            } catch (Exception e) {
                System.err.println("Could not write icons: " + e);
                System.exit(1);
            }
            return;
        }
        System.setProperty("awt.useSystemAAFontSettings", "on");
        System.setProperty("swing.aatext", "true");
        try {
            UIManager.setLookAndFeel(UIManager.getCrossPlatformLookAndFeelClassName());
        } catch (Exception ignored) {
            // keep default
        }
        UIManager.put("PopupMenu.background", CARD);
        UIManager.put("PopupMenu.border", BorderFactory.createLineBorder(BORDER));
        UIManager.put("MenuItem.background", CARD);
        UIManager.put("MenuItem.foreground", TEXT);
        UIManager.put("MenuItem.selectionBackground", SELECT);
        UIManager.put("MenuItem.selectionForeground", TEXT);
        UIManager.put("MenuItem.font", font(Font.PLAIN, 13));
        UIManager.put("MenuItem.border", new EmptyBorder(7, 14, 7, 14));
        UIManager.put("PopupMenuSeparator.background", CARD);
        UIManager.put("PopupMenuSeparator.foreground", BORDER);
        UIManager.put("Separator.background", CARD);
        UIManager.put("Separator.foreground", BORDER);
        SwingUtilities.invokeLater(() -> {
            try {
                if (Taskbar.isTaskbarSupported() && Taskbar.getTaskbar().isSupported(Taskbar.Feature.ICON_IMAGE)) {
                    Taskbar.getTaskbar().setIconImage(logoImage(256)); // macOS Dock / Windows taskbar
                }
            } catch (Exception ignored) {
                // not supported on this platform
            }
            start();
        });
    }

    // ------------------------------------------------------------------
    // App icon (drawn in code, also exported for the installers)
    // ------------------------------------------------------------------

    private static Image appIcon;

    static Image appIcon() {
        if (appIcon == null) {
            appIcon = logoImage(128);
        }
        return appIcon;
    }

    static BufferedImage logoImage(int size) {
        BufferedImage img = new BufferedImage(size, size, BufferedImage.TYPE_INT_ARGB);
        Graphics2D g = img.createGraphics();
        Logo logo = new Logo(size);
        logo.setSize(size, size);
        logo.paint(g);
        g.dispose();
        return img;
    }

    static byte[] png(BufferedImage img) throws IOException {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        ImageIO.write(img, "png", out);
        return out.toByteArray();
    }

    /** Windows .ico containing one 256x256 PNG image. */
    static byte[] ico(byte[] png256) {
        ByteBuffer b = ByteBuffer.allocate(22 + png256.length).order(java.nio.ByteOrder.LITTLE_ENDIAN);
        b.putShort((short) 0).putShort((short) 1).putShort((short) 1); // reserved, type=icon, count=1
        b.put((byte) 0).put((byte) 0).put((byte) 0).put((byte) 0);     // 256x256, no palette
        b.putShort((short) 1).putShort((short) 32);                    // planes, bits per pixel
        b.putInt(png256.length).putInt(22);                            // data size, data offset
        b.put(png256);
        return b.array();
    }

    /** macOS .icns containing 512x512 and 256x256 PNG images. */
    static byte[] icns(byte[] png512, byte[] png256) throws IOException {
        ByteArrayOutputStream bytes = new ByteArrayOutputStream();
        DataOutputStream out = new DataOutputStream(bytes);
        out.writeBytes("icns");
        out.writeInt(8 + 8 + png512.length + 8 + png256.length);
        out.writeBytes("ic09");
        out.writeInt(8 + png512.length);
        out.write(png512);
        out.writeBytes("ic08");
        out.writeInt(8 + png256.length);
        out.write(png256);
        out.flush();
        return bytes.toByteArray();
    }

    static void writeIcons(Path dir) throws IOException {
        Files.createDirectories(dir);
        byte[] p512 = png(logoImage(512));
        byte[] p256 = png(logoImage(256));
        Files.write(dir.resolve("icon.png"), p512);
        Files.write(dir.resolve("icon.ico"), ico(p256));
        Files.write(dir.resolve("icon.icns"), icns(p512, p256));
    }

    // ------------------------------------------------------------------
    // Startup flow
    // ------------------------------------------------------------------

    static void start() {
        if (Files.exists(vaultPath)) {
            unlock();
        } else {
            welcome();
        }
    }

    static void welcome() {
        boolean[] openExisting = {false};
        JComponent body = column(logoRow(),
                textBlock("No vault was found at:\n" + vaultPath.toAbsolutePath()
                        + "\n\nCreate a new vault, or open one you already use on another computer "
                        + "(for example a vault.dat inside Dropbox, OneDrive or Google Drive).", 420, MUTED));
        boolean create = dialog(null, "Welcome", "Let's set up your password vault.", body,
                "Create new vault", false, "Quit", null,
                "Open existing vault\u2026", () -> openExisting[0] = true);
        if (openExisting[0]) {
            JFileChooser fc = new JFileChooser();
            fc.setDialogTitle("Open existing vault file");
            if (fc.showOpenDialog(null) == JFileChooser.APPROVE_OPTION) {
                vaultPath = fc.getSelectedFile().toPath();
                try {
                    saveVaultPath(vaultPath);
                } catch (IOException ignored) {
                    // the vault still opens; it just won't be remembered
                }
                unlock();
            } else {
                welcome();
            }
            return;
        }
        if (create) {
            createVault();
        } else {
            System.exit(0);
        }
    }

    static void createVault() {
        JPasswordField p1 = new RoundedPasswordField(24);
        JPasswordField p2 = new RoundedPasswordField(24);
        JLabel warn = label("If you forget it, your data cannot be recovered.", font(Font.PLAIN, 12), MUTED);
        JComponent body = column(logoRow(), labeled("Master password (min " + MIN_MASTER_LENGTH + " characters)", p1),
                labeled("Confirm master password", p2), warn);
        Vault[] created = new Vault[1];
        boolean ok = dialog(null, "Create your vault", "Choose one strong master password.", body,
                "Create Vault", false, "Quit", () -> {
                    char[] a = p1.getPassword();
                    char[] b = p2.getPassword();
                    try {
                        if (a.length < MIN_MASTER_LENGTH) {
                            return "Master password must be at least " + MIN_MASTER_LENGTH + " characters.";
                        }
                        if (!Arrays.equals(a, b)) {
                            return "The passwords do not match.";
                        }
                        created[0] = Vault.create(vaultPath, a);
                        return null;
                    } catch (Exception ex) {
                        return "Could not create vault: " + ex.getMessage();
                    } finally {
                        Arrays.fill(a, '\0');
                        Arrays.fill(b, '\0');
                    }
                });
        if (!ok) {
            System.exit(0);
        }
        showMain(created[0]);
    }

    static void unlock() {
        JPasswordField pf = new RoundedPasswordField(24);
        JComponent body = column(logoRow(), labeled("Master password", pf));
        Vault[] opened = new Vault[1];
        boolean ok = dialog(null, "Welcome back", "Enter your master password to unlock the vault.", body,
                "Unlock", false, "Quit", () -> {
                    long wait = lockedUntil - System.currentTimeMillis();
                    if (wait > 0) {
                        return "Too many attempts. Try again in " + (wait / 1000 + 1) + " seconds.";
                    }
                    char[] pw = pf.getPassword();
                    try {
                        opened[0] = Vault.open(vaultPath, pw);
                        failedAttempts = 0;
                        return null;
                    } catch (AEADBadTagException ex) {
                        pf.setText("");
                        failedAttempts++;
                        if (failedAttempts >= 3) {
                            long secs = Math.min(60L, 5L * (failedAttempts - 2));
                            lockedUntil = System.currentTimeMillis() + secs * 1000;
                            return "Incorrect password. Locked for " + secs + " seconds.";
                        }
                        return "Incorrect master password.";
                    } catch (Exception ex) {
                        return "Could not open vault: " + ex.getMessage();
                    } finally {
                        Arrays.fill(pw, '\0');
                    }
                });
        if (!ok) {
            System.exit(0);
        }
        showMain(opened[0]);
    }

    static void showMain(Vault v) {
        new MainWindow(v, PasswordManager::unlock).setVisible(true);
    }

    // ------------------------------------------------------------------
    // Data model
    // ------------------------------------------------------------------

    static final class HistoryItem {
        final String password;
        final long when;

        HistoryItem(String password, long when) {
            this.password = password;
            this.when = when;
        }
    }

    static final class Entry {
        final String id; // stable identity, used to merge changes between devices
        String site;
        String username;
        String password;
        String notes;
        String url;
        String category;
        String totp; // Base32 secret for 2FA codes
        long updated; // when the password was last set
        long modified; // last change of any kind
        final List<HistoryItem> history = new ArrayList<>();
        boolean revealed; // UI state only, never saved

        Entry(String site, String username, String password, String notes) {
            this(site, username, password, notes, "", "", "");
        }

        Entry(String site, String username, String password, String notes,
              String url, String category, String totp) {
            this(UUID.randomUUID().toString(), site, username, password, notes, url, category, totp);
        }

        /** Full constructor: the first argument is the entry id. */
        Entry(String id, String site, String username, String password, String notes,
              String url, String category, String totp) {
            this.id = id;
            this.site = site;
            this.username = username;
            this.password = password;
            this.notes = notes;
            this.url = url;
            this.category = category;
            this.totp = totp;
            this.updated = System.currentTimeMillis();
            this.modified = this.updated;
        }

        /** Overwrites this entry's content with another version of the same entry. */
        void copyFrom(Entry o) {
            site = o.site;
            username = o.username;
            password = o.password;
            notes = o.notes;
            url = o.url;
            category = o.category;
            totp = o.totp;
            updated = o.updated;
            modified = o.modified;
            history.clear();
            history.addAll(o.history);
        }

        /** Applies edits; records the old password in history when it changed. */
        void applyEdit(Entry n) {
            if (!password.equals(n.password)) {
                history.add(0, new HistoryItem(password, updated));
                while (history.size() > MAX_HISTORY) {
                    history.remove(history.size() - 1);
                }
                updated = System.currentTimeMillis();
            }
            site = n.site;
            username = n.username;
            password = n.password;
            notes = n.notes;
            url = n.url;
            category = n.category;
            totp = n.totp;
            modified = System.currentTimeMillis();
        }
    }

    // ------------------------------------------------------------------
    // Encrypted vault
    // File layout: "PMV3" | salt (16) | IV (12) | AES-GCM ciphertext+tag
    // (older "PMV1"/"PMV2" files are still readable and upgraded on next save)
    //
    // Sync: the vault can live in a cloud-synced folder. Before every save the
    // file on disk is compared with what we last read; if another device changed
    // it, both versions are merged per entry (newest edit wins, deletions are
    // remembered as "tombstones") instead of one overwriting the other.
    // ------------------------------------------------------------------

    enum SaveStatus { SAVED, MERGED, CONFLICT_COPY }

    enum SyncStatus { UNCHANGED, MERGED, RETRY, NEEDS_RELOCK }

    static byte[] sha256(byte[] data) {
        try {
            return MessageDigest.getInstance("SHA-256").digest(data);
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException(e);
        }
    }

    /** Stable id for entries created before ids existed, so every device derives the same one. */
    static String legacyId(String site, String username, String password) {
        byte[] h = sha256((site + "\0" + username + "\0" + password).getBytes(StandardCharsets.UTF_8));
        StringBuilder sb = new StringBuilder("legacy-");
        for (int i = 0; i < 16; i++) {
            sb.append(String.format("%02x", h[i]));
        }
        return sb.toString();
    }

    static final class Vault {
        private static final int SALT_LEN = 16;
        private static final int IV_LEN = 12;
        private static final int PBKDF2_ITERATIONS = 210_000;

        private Path path;
        private byte[] salt;
        private SecretKey key;
        private byte[] lastHash; // SHA-256 of the vault file as we last read or wrote it
        final List<Entry> entries = new ArrayList<>();
        final Map<String, Long> tombstones = new HashMap<>(); // id -> time it was deleted
        int idleMinutes = 5;
        int clipboardSeconds = 30;
        int genLength = 20;
        int autoTypeDelay = 3;
        boolean autoTypeEnter = false;
        Path conflictCopy; // set when a conflicting save was written to a separate file

        private Vault(Path path, byte[] salt, SecretKey key) {
            this.path = path;
            this.salt = salt;
            this.key = key;
        }

        Path path() {
            return path;
        }

        static Vault create(Path path, char[] password) throws GeneralSecurityException, IOException {
            byte[] salt = randomBytes(SALT_LEN);
            Vault v = new Vault(path, salt, deriveKey(password, salt));
            v.writeFile(false);
            return v;
        }

        static Vault open(Path path, char[] password) throws GeneralSecurityException, IOException {
            byte[] data = Files.readAllBytes(path);
            checkHeader(data);
            byte[] salt = Arrays.copyOfRange(data, 4, 4 + SALT_LEN);
            Vault shell = new Vault(path, salt, deriveKey(password, salt));
            Vault v = shell.decryptSnapshot(data); // AEADBadTagException if wrong password
            v.lastHash = sha256(data);
            return v;
        }

        private static int checkHeader(byte[] data) throws IOException {
            int header = 4 + SALT_LEN + IV_LEN;
            if (data.length < header + 16 || data[0] != 'P' || data[1] != 'M' || data[2] != 'V'
                    || data[3] < '1' || data[3] > '3') {
                throw new IOException("Not a valid vault file.");
            }
            return data[3] - '0';
        }

        /** Decrypts vault file bytes with this vault's key into a new, separate Vault object. */
        private Vault decryptSnapshot(byte[] data) throws GeneralSecurityException, IOException {
            int version = checkHeader(data);
            int header = 4 + SALT_LEN + IV_LEN;
            byte[] iv = Arrays.copyOfRange(data, 4 + SALT_LEN, header);
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec(128, iv));
            byte[] plain = cipher.doFinal(Arrays.copyOfRange(data, header, data.length));
            Vault v = new Vault(path, salt, key);
            v.deserialize(plain, version);
            return v;
        }

        /** Like decryptSnapshot, but returns null if the file uses a different key (new master password). */
        private Vault readSnapshot(byte[] disk) throws GeneralSecurityException, IOException {
            checkHeader(disk);
            if (!Arrays.equals(Arrays.copyOfRange(disk, 4, 4 + SALT_LEN), salt)) {
                return null;
            }
            return decryptSnapshot(disk);
        }

        /** True if the given password matches this vault's master password. */
        boolean verify(char[] password) throws GeneralSecurityException {
            return MessageDigest.isEqual(deriveKey(password, salt).getEncoded(), key.getEncoded());
        }

        /** Re-encrypts the vault under a new master password (new salt, new key). */
        void changeMasterPassword(char[] newPassword) throws GeneralSecurityException, IOException {
            SyncStatus s = syncFromDisk();
            if (s == SyncStatus.NEEDS_RELOCK || s == SyncStatus.RETRY) {
                throw new IOException("The vault file was changed elsewhere. Lock and reopen it, then try again.");
            }
            byte[] oldSalt = salt;
            SecretKey oldKey = key;
            try {
                salt = randomBytes(SALT_LEN);
                key = deriveKey(newPassword, salt);
                writeFile(false);
                // the backup is still encrypted with the OLD password, so remove it
                Files.deleteIfExists(backupPath());
            } catch (GeneralSecurityException | IOException | RuntimeException e) {
                salt = oldSalt;
                key = oldKey;
                throw e;
            }
        }

        private Path backupPath() {
            return path.resolveSibling(path.getFileName() + ".bak");
        }

        private byte[] fileBytes() throws GeneralSecurityException, IOException {
            byte[] iv = randomBytes(IV_LEN);
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(128, iv));
            byte[] ciphertext = cipher.doFinal(serialize());

            ByteArrayOutputStream out = new ByteArrayOutputStream();
            out.write(new byte[]{'P', 'M', 'V', '3'});
            out.write(salt);
            out.write(iv);
            out.write(ciphertext);
            return out.toByteArray();
        }

        private void writeFile(boolean keepBackup) throws GeneralSecurityException, IOException {
            byte[] data = fileBytes();
            Path dir = path.toAbsolutePath().getParent();
            if (dir != null) {
                Files.createDirectories(dir);
            }
            if (keepBackup && Files.exists(path)) {
                Files.copy(path, backupPath(), StandardCopyOption.REPLACE_EXISTING);
            }
            // Write to a temp file first so a crash can never corrupt the vault
            Path tmp = path.resolveSibling(path.getFileName() + ".tmp");
            Files.write(tmp, data);
            try {
                Files.move(tmp, path, StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING);
            } catch (AtomicMoveNotSupportedException e) {
                Files.move(tmp, path, StandardCopyOption.REPLACE_EXISTING);
            }
            lastHash = sha256(data);
        }

        /**
         * Saves the vault. If another device changed the file since we last read it,
         * the two versions are merged first so nothing is lost.
         */
        SaveStatus save(boolean keepBackup) throws GeneralSecurityException, IOException {
            if (lastHash != null && Files.exists(path)) {
                byte[] disk = Files.readAllBytes(path);
                if (!Arrays.equals(sha256(disk), lastHash)) {
                    Vault remote = readSnapshot(disk);
                    if (remote == null) {
                        // encrypted with a different key: never overwrite it, keep ours beside it
                        conflictCopy = writeConflictCopy();
                        return SaveStatus.CONFLICT_COPY;
                    }
                    mergeFrom(remote);
                    writeFile(keepBackup);
                    return SaveStatus.MERGED;
                }
            }
            writeFile(keepBackup);
            return SaveStatus.SAVED;
        }

        private Path writeConflictCopy() throws GeneralSecurityException, IOException {
            String stamp = DateTimeFormatter.ofPattern("yyyyMMdd-HHmmss")
                    .withZone(ZoneId.systemDefault()).format(Instant.now());
            Path p = path.resolveSibling("vault-conflict-" + stamp + ".dat");
            Files.write(p, fileBytes());
            return p;
        }

        /** Picks up changes another device made to the vault file. */
        SyncStatus syncFromDisk() throws IOException {
            if (lastHash == null || !Files.exists(path)) {
                return SyncStatus.UNCHANGED;
            }
            byte[] disk = Files.readAllBytes(path);
            if (Arrays.equals(sha256(disk), lastHash)) {
                return SyncStatus.UNCHANGED;
            }
            try {
                Vault remote = readSnapshot(disk);
                if (remote == null) {
                    return SyncStatus.NEEDS_RELOCK;
                }
                mergeFrom(remote);
                lastHash = sha256(disk);
                return SyncStatus.MERGED;
            } catch (GeneralSecurityException | IOException e) {
                return SyncStatus.RETRY; // probably still being written by the sync service
            }
        }

        /** Merges another version of the vault into this one, in place. Newest edit wins. */
        void mergeFrom(Vault remote) {
            for (Map.Entry<String, Long> t : remote.tombstones.entrySet()) {
                tombstones.merge(t.getKey(), t.getValue(), Math::max);
            }
            Map<String, Entry> mine = new HashMap<>();
            for (Entry e : entries) {
                mine.put(e.id, e);
            }
            for (Entry r : remote.entries) {
                Entry m = mine.get(r.id);
                if (m == null) {
                    Long dead = tombstones.get(r.id);
                    if (dead == null || dead < r.modified) {
                        entries.add(r);
                    }
                } else if (r.modified > m.modified) {
                    m.copyFrom(r);
                }
            }
            entries.removeIf(e -> {
                Long dead = tombstones.get(e.id);
                return dead != null && dead >= e.modified;
            });
            long cutoff = System.currentTimeMillis() - TOMBSTONE_KEEP_MS;
            tombstones.values().removeIf(v -> v < cutoff);
        }

        void recordDeletion(Entry e) {
            tombstones.put(e.id, System.currentTimeMillis());
        }

        void restore(Entry e) {
            tombstones.remove(e.id);
            e.modified = System.currentTimeMillis();
        }

        /** Copies the vault file to a new location and starts using it. The old file is left in place. */
        Path moveTo(Path newPath) throws GeneralSecurityException, IOException {
            syncFromDisk();
            save(false); // make sure the file on disk matches our latest state
            if (Files.exists(newPath)) {
                throw new IOException("A file already exists at that location.");
            }
            byte[] data = Files.readAllBytes(path);
            Path parent = newPath.toAbsolutePath().getParent();
            if (parent != null) {
                Files.createDirectories(parent);
            }
            Files.write(newPath, data);
            if (!Arrays.equals(Files.readAllBytes(newPath), data)) {
                Files.deleteIfExists(newPath);
                throw new IOException("Copy could not be verified.");
            }
            Path old = path;
            path = newPath;
            lastHash = sha256(data);
            return old;
        }

        void setPath(Path p) {
            path = p;
        }

        static void deleteVaultFiles(Path p) throws IOException {
            Files.deleteIfExists(p);
            Files.deleteIfExists(p.resolveSibling(p.getFileName() + ".bak"));
        }

        void lock() {
            entries.clear();
            tombstones.clear();
        }

        private byte[] serialize() throws IOException {
            ByteArrayOutputStream bytes = new ByteArrayOutputStream();
            DataOutputStream out = new DataOutputStream(bytes);
            out.writeInt(entries.size());
            for (Entry e : entries) {
                out.writeUTF(e.id);
                out.writeUTF(e.site);
                out.writeUTF(e.username);
                out.writeUTF(e.password);
                out.writeUTF(e.notes);
                out.writeUTF(e.url);
                out.writeUTF(e.category);
                out.writeUTF(e.totp);
                out.writeLong(e.updated);
                out.writeLong(e.modified);
                out.writeInt(e.history.size());
                for (HistoryItem h : e.history) {
                    out.writeUTF(h.password);
                    out.writeLong(h.when);
                }
            }
            out.writeInt(tombstones.size());
            for (Map.Entry<String, Long> t : tombstones.entrySet()) {
                out.writeUTF(t.getKey());
                out.writeLong(t.getValue());
            }
            out.writeInt(idleMinutes);
            out.writeInt(clipboardSeconds);
            out.writeInt(genLength);
            out.writeInt(autoTypeDelay);
            out.writeInt(autoTypeEnter ? 1 : 0);
            out.flush();
            return bytes.toByteArray();
        }

        private void deserialize(byte[] plain, int version) throws IOException {
            DataInputStream in = new DataInputStream(new ByteArrayInputStream(plain));
            int n = in.readInt();
            if (n < 0 || n > 1_000_000) {
                throw new IOException("Vault data is corrupted.");
            }
            entries.clear();
            tombstones.clear();
            for (int i = 0; i < n; i++) {
                if (version == 1) {
                    String s = in.readUTF();
                    String u = in.readUTF();
                    String p = in.readUTF();
                    String no = in.readUTF();
                    entries.add(new Entry(legacyId(s, u, p), s, u, p, no, "", "", ""));
                } else {
                    String id = version >= 3 ? in.readUTF() : null;
                    String s = in.readUTF();
                    String u = in.readUTF();
                    String p = in.readUTF();
                    String no = in.readUTF();
                    String url = in.readUTF();
                    String cat = in.readUTF();
                    String totp = in.readUTF();
                    long updated = in.readLong();
                    long modified = version >= 3 ? in.readLong() : updated;
                    Entry e = new Entry(id != null ? id : legacyId(s, u, p), s, u, p, no, url, cat, totp);
                    e.updated = updated;
                    e.modified = modified;
                    int h = in.readInt();
                    if (h < 0 || h > 1000) {
                        throw new IOException("Vault data is corrupted.");
                    }
                    for (int k = 0; k < h; k++) {
                        e.history.add(new HistoryItem(in.readUTF(), in.readLong()));
                    }
                    entries.add(e);
                }
            }
            if (version >= 3) {
                int t = in.readInt();
                if (t < 0 || t > 1_000_000) {
                    throw new IOException("Vault data is corrupted.");
                }
                for (int i = 0; i < t; i++) {
                    tombstones.put(in.readUTF(), in.readLong());
                }
            }
            if (version >= 2) {
                idleMinutes = in.readInt();
                clipboardSeconds = in.readInt();
                genLength = in.readInt();
            }
            if (version >= 3) {
                autoTypeDelay = in.readInt();
                autoTypeEnter = in.readInt() != 0;
            }
        }

        private static SecretKey deriveKey(char[] password, byte[] salt) throws GeneralSecurityException {
            SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
            PBEKeySpec spec = new PBEKeySpec(password, salt, PBKDF2_ITERATIONS, 256);
            try {
                return new SecretKeySpec(factory.generateSecret(spec).getEncoded(), "AES");
            } finally {
                spec.clearPassword();
            }
        }

        private static byte[] randomBytes(int n) {
            byte[] b = new byte[n];
            RNG.nextBytes(b);
            return b;
        }
    }

    // ------------------------------------------------------------------
    // Password utilities: generator, strength, audit, breach check
    // ------------------------------------------------------------------

    static String generatePassword(int length) {
        length = Math.max(8, length);
        String lower = "abcdefghijkmnopqrstuvwxyz";
        String upper = "ABCDEFGHJKLMNPQRSTUVWXYZ";
        String digits = "23456789";
        String symbols = "!@#$%^&*-_=+?";
        String all = lower + upper + digits + symbols;
        String[] sets = {lower, upper, digits, symbols};

        char[] out = new char[length];
        for (int i = 0; i < sets.length; i++) {
            out[i] = sets[i].charAt(RNG.nextInt(sets[i].length()));
        }
        for (int i = sets.length; i < length; i++) {
            out[i] = all.charAt(RNG.nextInt(all.length()));
        }
        for (int i = out.length - 1; i > 0; i--) { // Fisher-Yates shuffle
            int j = RNG.nextInt(i + 1);
            char t = out[i];
            out[i] = out[j];
            out[j] = t;
        }
        return new String(out);
    }

    /** Returns 0 (very weak) to 5 (excellent). */
    static int strengthScore(String p) {
        int score = 0;
        if (p.length() >= 12) score++;
        if (p.length() >= 16) score++;
        if (p.chars().anyMatch(Character::isLowerCase) && p.chars().anyMatch(Character::isUpperCase)) score++;
        if (p.chars().anyMatch(Character::isDigit)) score++;
        if (p.chars().anyMatch(c -> !Character.isLetterOrDigit(c))) score++;
        return score;
    }

    static final class AuditResult {
        int total;
        int healthy;
        final List<String> lines = new ArrayList<>();

        int percent() {
            return total == 0 ? 100 : Math.round(100f * healthy / total);
        }
    }

    static AuditResult audit(List<Entry> entries, long now) {
        AuditResult r = new AuditResult();
        Map<String, Integer> counts = new HashMap<>();
        for (Entry e : entries) {
            counts.merge(e.password, 1, Integer::sum);
        }
        for (Entry e : entries) {
            r.total++;
            List<String> issues = new ArrayList<>();
            if (strengthScore(e.password) <= 2) issues.add("weak password");
            if (counts.get(e.password) > 1) issues.add("password reused");
            long days = (now - e.updated) / 86_400_000L;
            if (days > OLD_PASSWORD_DAYS) issues.add("not changed in " + days + " days");
            if (issues.isEmpty()) {
                r.healthy++;
            } else {
                r.lines.add("\u2022 " + e.site + " \u2014 " + String.join(", ", issues));
            }
        }
        return r;
    }

    /**
     * Have I Been Pwned range lookup. Only the first 5 characters of the SHA-1
     * hash leave this computer (k-anonymity); the password is never sent.
     */
    static long pwnedCount(String password) throws Exception {
        MessageDigest md = MessageDigest.getInstance("SHA-1");
        byte[] d = md.digest(password.getBytes(StandardCharsets.UTF_8));
        StringBuilder sb = new StringBuilder();
        for (byte b : d) {
            sb.append(String.format("%02X", b));
        }
        String hash = sb.toString();
        String prefix = hash.substring(0, 5);
        String suffix = hash.substring(5);
        HttpClient client = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(8)).build();
        HttpRequest req = HttpRequest.newBuilder(URI.create("https://api.pwnedpasswords.com/range/" + prefix))
                .timeout(Duration.ofSeconds(10))
                .header("Add-Padding", "true")
                .header("User-Agent", "PasswordManager-Desktop")
                .GET().build();
        HttpResponse<String> resp = client.send(req, HttpResponse.BodyHandlers.ofString());
        if (resp.statusCode() != 200) {
            throw new IOException("Service returned HTTP " + resp.statusCode());
        }
        for (String line : resp.body().split("\\r?\\n")) {
            int i = line.indexOf(':');
            if (i > 0 && line.substring(0, i).equalsIgnoreCase(suffix)) {
                return Long.parseLong(line.substring(i + 1).trim());
            }
        }
        return 0;
    }

    // ------------------------------------------------------------------
    // TOTP (RFC 6238): 6-digit codes, 30-second steps, HMAC-SHA1
    // ------------------------------------------------------------------

    static final class Totp {
        static byte[] base32Decode(String s) {
            String clean = s.replace(" ", "").replace("-", "").toUpperCase().replaceAll("=+$", "");
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            int buffer = 0;
            int bits = 0;
            for (char c : clean.toCharArray()) {
                int v;
                if (c >= 'A' && c <= 'Z') v = c - 'A';
                else if (c >= '2' && c <= '7') v = c - '2' + 26;
                else throw new IllegalArgumentException("Invalid Base32 character: " + c);
                buffer = (buffer << 5) | v;
                bits += 5;
                if (bits >= 8) {
                    out.write((buffer >> (bits - 8)) & 0xFF);
                    bits -= 8;
                }
            }
            return out.toByteArray();
        }

        static String code(String secret, long timeMillis) throws GeneralSecurityException {
            byte[] key = base32Decode(secret);
            if (key.length == 0) {
                throw new IllegalArgumentException("Empty secret");
            }
            long counter = timeMillis / 1000 / 30;
            byte[] msg = ByteBuffer.allocate(8).putLong(counter).array();
            Mac mac = Mac.getInstance("HmacSHA1");
            mac.init(new SecretKeySpec(key, "HmacSHA1"));
            byte[] h = mac.doFinal(msg);
            int off = h[h.length - 1] & 0x0F;
            int bin = ((h[off] & 0x7F) << 24) | ((h[off + 1] & 0xFF) << 16)
                    | ((h[off + 2] & 0xFF) << 8) | (h[off + 3] & 0xFF);
            return String.format("%06d", bin % 1_000_000);
        }
    }

    // ------------------------------------------------------------------
    // Auto-type: types a login into the application you were using before
    // ------------------------------------------------------------------

    /** What to type for a mode: "login", "password" or "totp". "\t" is Tab, "\n" is Enter. */
    static List<String> autoTypeSequence(Entry e, String mode, boolean enter, long now)
            throws GeneralSecurityException {
        List<String> seq = new ArrayList<>();
        switch (mode) {
            case "login":
                if (!e.username.isEmpty()) {
                    seq.add(e.username);
                    seq.add("\t");
                }
                seq.add(e.password);
                break;
            case "password":
                seq.add(e.password);
                break;
            case "totp":
                seq.add(Totp.code(e.totp, now));
                break;
            default:
                throw new IllegalArgumentException("Unknown auto-type mode: " + mode);
        }
        if (enter) {
            seq.add("\n");
        }
        return seq;
    }

    /**
     * Types the sequence into whatever window has focus. Text is pasted (Ctrl+V / Cmd+V) rather
     * than typed key by key, because that works with every character and keyboard layout. The
     * previous clipboard text is restored afterwards. Must not run on the Swing thread.
     */
    static void typeSequence(List<String> seq) throws AWTException {
        Robot robot = new Robot();
        robot.setAutoDelay(30);
        Clipboard cb = Toolkit.getDefaultToolkit().getSystemClipboard();
        String previous = null;
        try {
            if (cb.isDataFlavorAvailable(DataFlavor.stringFlavor)) {
                previous = (String) cb.getData(DataFlavor.stringFlavor);
            }
        } catch (Exception ignored) {
            // clipboard unreadable: it will simply be cleared afterwards
        }
        int modifier = System.getProperty("os.name", "").toLowerCase().contains("mac")
                ? KeyEvent.VK_META : KeyEvent.VK_CONTROL;
        try {
            for (String part : seq) {
                if (part.equals("\t")) {
                    robot.keyPress(KeyEvent.VK_TAB);
                    robot.keyRelease(KeyEvent.VK_TAB);
                } else if (part.equals("\n")) {
                    robot.keyPress(KeyEvent.VK_ENTER);
                    robot.keyRelease(KeyEvent.VK_ENTER);
                } else {
                    cb.setContents(new StringSelection(part), null);
                    robot.delay(80);
                    robot.keyPress(modifier);
                    robot.keyPress(KeyEvent.VK_V);
                    robot.keyRelease(KeyEvent.VK_V);
                    robot.keyRelease(modifier);
                    robot.delay(150);
                }
                robot.delay(80);
            }
        } finally {
            cb.setContents(new StringSelection(previous == null ? "" : previous), null);
        }
    }

    // ------------------------------------------------------------------
    // CSV import / export
    // ------------------------------------------------------------------

    static List<List<String>> parseCsv(String text) {
        List<List<String>> rows = new ArrayList<>();
        List<String> row = new ArrayList<>();
        StringBuilder f = new StringBuilder();
        boolean quoted = false;
        boolean any = false;
        for (int i = 0; i < text.length(); i++) {
            char c = text.charAt(i);
            if (quoted) {
                if (c == '"') {
                    if (i + 1 < text.length() && text.charAt(i + 1) == '"') {
                        f.append('"');
                        i++;
                    } else {
                        quoted = false;
                    }
                } else {
                    f.append(c);
                }
            } else if (c == '"') {
                quoted = true;
                any = true;
            } else if (c == ',') {
                row.add(f.toString());
                f.setLength(0);
                any = true;
            } else if (c == '\n' || c == '\r') {
                if (c == '\r' && i + 1 < text.length() && text.charAt(i + 1) == '\n') i++;
                if (any || f.length() > 0 || !row.isEmpty()) {
                    row.add(f.toString());
                    rows.add(row);
                }
                row = new ArrayList<>();
                f.setLength(0);
                any = false;
            } else {
                f.append(c);
                any = true;
            }
        }
        if (any || f.length() > 0 || !row.isEmpty()) {
            row.add(f.toString());
            rows.add(row);
        }
        return rows;
    }

    private static int findColumn(List<String> header, String... names) {
        for (String n : names) {
            for (int i = 0; i < header.size(); i++) {
                if (header.get(i).trim().toLowerCase().equals(n)) return i;
            }
        }
        return -1;
    }

    private static String cell(List<String> row, int idx) {
        return idx >= 0 && idx < row.size() ? row.get(idx).trim() : "";
    }

    private static String hostOf(String url) {
        if (url.isEmpty()) return "";
        try {
            String u = url.contains("://") ? url : "https://" + url;
            String h = URI.create(u).getHost();
            return h == null ? url : h;
        } catch (Exception e) {
            return url;
        }
    }

    /** Understands Chrome, Bitwarden and this app's own CSV export. */
    static List<Entry> parseCsvEntries(String text) throws IOException {
        if (text.startsWith("\uFEFF")) text = text.substring(1);
        List<List<String>> rows = parseCsv(text);
        if (rows.isEmpty()) {
            throw new IOException("The file is empty.");
        }
        List<String> header = rows.get(0);
        int name = findColumn(header, "name", "title", "site");
        int url = findColumn(header, "url", "login_uri", "website");
        int user = findColumn(header, "username", "login_username", "login", "email");
        int pass = findColumn(header, "password", "login_password");
        int notes = findColumn(header, "notes", "note", "extra");
        int cat = findColumn(header, "category", "folder", "grouping");
        int totp = findColumn(header, "totp", "login_totp", "otp");
        if (pass < 0) {
            throw new IOException("Could not find a password column in the file.");
        }
        List<Entry> out = new ArrayList<>();
        for (int i = 1; i < rows.size(); i++) {
            List<String> r = rows.get(i);
            String pw = cell(r, pass);
            if (pw.isEmpty()) continue;
            String u = cell(r, url);
            String site = cell(r, name);
            if (site.isEmpty()) site = hostOf(u);
            if (site.isEmpty()) site = "Imported";
            out.add(new Entry(site, cell(r, user), pw, cell(r, notes), u, cell(r, cat),
                    cell(r, totp).replace(" ", "").toUpperCase()));
        }
        return out;
    }

    /** Old "username:password" lines (the first version of this app). */
    static List<Entry> parseColonList(String text) {
        List<Entry> out = new ArrayList<>();
        for (String line : text.split("\\r?\\n")) {
            int i = line.indexOf(':');
            if (i <= 0 || i == line.length() - 1) continue;
            out.add(new Entry("Imported (passwords.txt)", line.substring(0, i).trim(), line.substring(i + 1), ""));
        }
        return out;
    }

    static String toCsv(List<Entry> entries) {
        StringBuilder sb = new StringBuilder("name,url,username,password,notes,category,totp\n");
        for (Entry e : entries) {
            String[] f = {e.site, e.url, e.username, e.password, e.notes, e.category, e.totp};
            for (int i = 0; i < f.length; i++) {
                if (i > 0) sb.append(',');
                sb.append('"').append(f[i].replace("\"", "\"\"")).append('"');
            }
            sb.append('\n');
        }
        return sb.toString();
    }

    static String formatTime(long millis) {
        return DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm")
                .withZone(ZoneId.systemDefault()).format(Instant.ofEpochMilli(millis));
    }

    static DocumentListener onChange(Runnable r) {
        return new DocumentListener() {
            public void insertUpdate(DocumentEvent e) { r.run(); }
            public void removeUpdate(DocumentEvent e) { r.run(); }
            public void changedUpdate(DocumentEvent e) { r.run(); }
        };
    }

    // ------------------------------------------------------------------
    // UI building blocks
    // ------------------------------------------------------------------

    static Graphics2D aa(Graphics g) {
        Graphics2D g2 = (Graphics2D) g.create();
        g2.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);
        g2.setRenderingHint(RenderingHints.KEY_TEXT_ANTIALIASING, RenderingHints.VALUE_TEXT_ANTIALIAS_ON);
        return g2;
    }

    static Color mix(Color a, Color b, double t) {
        return new Color(
                (int) (a.getRed() + (b.getRed() - a.getRed()) * t),
                (int) (a.getGreen() + (b.getGreen() - a.getGreen()) * t),
                (int) (a.getBlue() + (b.getBlue() - a.getBlue()) * t));
    }

    static JLabel label(String text, Font f, Color c) {
        JLabel l = new JLabel(text);
        l.setFont(f);
        l.setForeground(c);
        return l;
    }

    /** Wrapping text label (HTML-escaped). */
    static JLabel textBlock(String text, int width, Color c) {
        String esc = text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace("\n", "<br>");
        JLabel l = new JLabel("<html><body style='width:" + width + "px'>" + esc + "</body></html>");
        l.setFont(font(Font.PLAIN, 13));
        l.setForeground(c);
        return l;
    }

    /** Small caption above a component. */
    static JPanel labeled(String caption, JComponent c) {
        JPanel p = new JPanel(new BorderLayout(0, 6));
        p.setOpaque(false);
        p.add(label(caption, font(Font.BOLD, 12), MUTED), BorderLayout.NORTH);
        p.add(c, BorderLayout.CENTER);
        return p;
    }

    /** Two components side by side. */
    static JPanel pair(JComponent a, JComponent b) {
        JPanel p = new JPanel(new GridLayout(1, 2, 12, 0));
        p.setOpaque(false);
        p.add(a);
        p.add(b);
        return p;
    }

    /** Vertical stack with even spacing. */
    static JPanel column(JComponent... items) {
        JPanel p = new JPanel();
        p.setOpaque(false);
        p.setLayout(new BoxLayout(p, BoxLayout.Y_AXIS));
        for (int i = 0; i < items.length; i++) {
            items[i].setAlignmentX(Component.LEFT_ALIGNMENT);
            p.add(items[i]);
            if (i < items.length - 1) {
                p.add(Box.createVerticalStrut(14));
            }
        }
        return p;
    }

    static JComponent logoRow() {
        JPanel p = new JPanel(new FlowLayout(FlowLayout.CENTER, 0, 0));
        p.setOpaque(false);
        p.add(new Logo(64));
        return p;
    }

    static JMenuItem menuItem(String text, java.awt.event.ActionListener a) {
        JMenuItem mi = new JMenuItem(text);
        mi.addActionListener(a);
        return mi;
    }

    static void styleText(JTextComponent c) {
        c.setForeground(TEXT);
        c.setCaretColor(TEXT);
        c.setSelectionColor(ACCENT);
        c.setSelectedTextColor(Color.WHITE);
        c.setFont(font(Font.PLAIN, 14));
    }

    static void paintFieldFrame(Graphics g, JComponent c) {
        Graphics2D g2 = aa(g);
        g2.setColor(FIELD);
        g2.fillRoundRect(0, 0, c.getWidth() - 1, c.getHeight() - 1, 12, 12);
        g2.setColor(c.hasFocus() ? ACCENT : BORDER);
        g2.drawRoundRect(0, 0, c.getWidth() - 1, c.getHeight() - 1, 12, 12);
        g2.dispose();
    }

    static void prepareField(JTextComponent c) {
        styleText(c);
        c.setOpaque(false);
        c.setBorder(new EmptyBorder(9, 12, 9, 12));
        c.addFocusListener(new FocusAdapter() {
            @Override public void focusGained(FocusEvent e) { c.repaint(); }
            @Override public void focusLost(FocusEvent e) { c.repaint(); }
        });
    }

    static final class RoundedTextField extends JTextField {
        String placeholder;

        RoundedTextField(int columns) {
            super(columns);
            prepareField(this);
        }

        @Override
        protected void paintComponent(Graphics g) {
            paintFieldFrame(g, this);
            super.paintComponent(g);
            if (placeholder != null && getText().isEmpty() && !hasFocus()) {
                Graphics2D g2 = aa(g);
                g2.setFont(getFont());
                g2.setColor(MUTED);
                FontMetrics fm = g2.getFontMetrics();
                g2.drawString(placeholder, getInsets().left, (getHeight() + fm.getAscent() - fm.getDescent()) / 2);
                g2.dispose();
            }
        }
    }

    static final class RoundedPasswordField extends JPasswordField {
        RoundedPasswordField(int columns) {
            super(columns);
            prepareField(this);
        }

        @Override
        protected void paintComponent(Graphics g) {
            paintFieldFrame(g, this);
            super.paintComponent(g);
        }
    }

    static class RoundedPanel extends JPanel {
        private final Color fill;
        private final Color line;
        private final int arc;

        RoundedPanel(LayoutManager lm, Color fill, Color line, int arc) {
            super(lm);
            this.fill = fill;
            this.line = line;
            this.arc = arc;
            setOpaque(false);
        }

        @Override
        protected void paintComponent(Graphics g) {
            Graphics2D g2 = aa(g);
            g2.setColor(fill);
            g2.fillRoundRect(0, 0, getWidth() - 1, getHeight() - 1, arc, arc);
            if (line != null) {
                g2.setColor(line);
                g2.drawRoundRect(0, 0, getWidth() - 1, getHeight() - 1, arc, arc);
            }
            g2.dispose();
            super.paintComponent(g);
        }
    }

    enum Kind { PRIMARY, SECONDARY, DANGER, GHOST }

    static final class RoundedButton extends JButton {
        private final Kind kind;
        private boolean hover;
        private boolean pressed;

        RoundedButton(String text, Kind kind) {
            super(text);
            this.kind = kind;
            setContentAreaFilled(false);
            setBorderPainted(false);
            setFocusPainted(false);
            setOpaque(false);
            setFont(font(Font.BOLD, 13));
            setCursor(Cursor.getPredefinedCursor(Cursor.HAND_CURSOR));
            setBorder(new EmptyBorder(9, 16, 9, 16));
            setForeground(kind == Kind.PRIMARY || kind == Kind.DANGER ? Color.WHITE
                    : kind == Kind.GHOST ? MUTED : TEXT);
            addMouseListener(new MouseAdapter() {
                @Override public void mouseEntered(MouseEvent e) { hover = true; repaint(); }
                @Override public void mouseExited(MouseEvent e) { hover = false; pressed = false; repaint(); }
                @Override public void mousePressed(MouseEvent e) { pressed = true; repaint(); }
                @Override public void mouseReleased(MouseEvent e) { pressed = false; repaint(); }
            });
        }

        @Override
        protected void paintComponent(Graphics g) {
            Graphics2D g2 = aa(g);
            Color base;
            switch (kind) {
                case PRIMARY: base = ACCENT; break;
                case DANGER: base = DANGER; break;
                case SECONDARY: base = CARD; break;
                default: base = BG; break;
            }
            Color fill = base;
            if (pressed) fill = mix(base, Color.BLACK, 0.18);
            else if (hover) fill = mix(base, Color.WHITE, kind == Kind.GHOST ? 0.07 : 0.12);
            if (!isEnabled()) fill = mix(base, BG, 0.5);
            if (kind != Kind.GHOST || hover) {
                g2.setColor(fill);
                g2.fillRoundRect(0, 0, getWidth() - 1, getHeight() - 1, 12, 12);
            }
            if (kind == Kind.SECONDARY) {
                g2.setColor(hover ? mix(BORDER, Color.WHITE, 0.2) : BORDER);
                g2.drawRoundRect(0, 0, getWidth() - 1, getHeight() - 1, 12, 12);
            }
            g2.dispose();
            super.paintComponent(g);
        }
    }

    static RoundedButton button(String text, Kind kind, java.awt.event.ActionListener a) {
        RoundedButton b = new RoundedButton(text, kind);
        b.addActionListener(a);
        return b;
    }

    /** App logo: gradient tile with a padlock. */
    static final class Logo extends JComponent {
        private final int size;

        Logo(int size) {
            this.size = size;
            setPreferredSize(new Dimension(size, size));
            setMinimumSize(new Dimension(size, size));
            setMaximumSize(new Dimension(size, size));
        }

        @Override
        protected void paintComponent(Graphics g) {
            Graphics2D g2 = aa(g);
            g2.setPaint(new GradientPaint(0, 0, ACCENT, size, size, ACCENT_2));
            g2.fillRoundRect(0, 0, size, size, (int) (size * 0.3), (int) (size * 0.3));
            g2.setColor(Color.WHITE);
            double bw = size * 0.42;
            double bh = size * 0.30;
            double bx = (size - bw) / 2;
            double by = size * 0.47;
            g2.setStroke(new BasicStroke(Math.max(2f, size * 0.07f), BasicStroke.CAP_ROUND, BasicStroke.JOIN_ROUND));
            double sw = bw * 0.62;
            g2.drawArc((int) ((size - sw) / 2), (int) (size * 0.22), (int) sw, (int) (size * 0.5), 0, 180);
            g2.drawLine((int) ((size - sw) / 2), (int) (size * 0.47), (int) ((size - sw) / 2), (int) by);
            g2.drawLine((int) ((size + sw) / 2), (int) (size * 0.47), (int) ((size + sw) / 2), (int) by);
            g2.fillRoundRect((int) bx, (int) by, (int) bw, (int) bh, 8, 8);
            g2.setColor(mix(ACCENT, ACCENT_2, 0.5));
            int d = Math.max(4, (int) (size * 0.09));
            g2.fillOval(size / 2 - d / 2, (int) (by + bh / 2 - d / 2), d, d);
            g2.dispose();
        }
    }

    /** Five-segment password strength meter. */
    static final class StrengthBar extends JComponent {
        private int score = -1;

        StrengthBar() {
            setPreferredSize(new Dimension(100, 20));
        }

        void setScore(int s) {
            score = s;
            repaint();
        }

        @Override
        protected void paintComponent(Graphics g) {
            Graphics2D g2 = aa(g);
            int gap = 5;
            int segW = (getWidth() - gap * 4) / 5;
            int h = 6;
            int y = (getHeight() - h) / 2;
            Color on = score >= 4 ? GOOD : score >= 3 ? WARN : score >= 2 ? new Color(0xD9822B) : DANGER;
            for (int i = 0; i < 5; i++) {
                g2.setColor(i < score ? on : BORDER);
                g2.fillRoundRect(i * (segW + gap), y, segW, h, h, h);
            }
            g2.dispose();
        }
    }

    /** Thin horizontal progress line (used for the 2FA countdown). */
    static final class ProgressLine extends JComponent {
        private double fraction = 1;

        ProgressLine() {
            setPreferredSize(new Dimension(100, 10));
        }

        void setFraction(double f) {
            fraction = f;
            repaint();
        }

        @Override
        protected void paintComponent(Graphics g) {
            Graphics2D g2 = aa(g);
            int h = 6;
            int y = (getHeight() - h) / 2;
            g2.setColor(BORDER);
            g2.fillRoundRect(0, y, getWidth(), h, h, h);
            g2.setColor(fraction < 0.2 ? DANGER : ACCENT);
            g2.fillRoundRect(0, y, (int) (getWidth() * fraction), h, h, h);
            g2.dispose();
        }
    }

    static final class SlimScrollBarUI extends BasicScrollBarUI {
        @Override
        protected JButton createDecreaseButton(int orientation) {
            return zero();
        }

        @Override
        protected JButton createIncreaseButton(int orientation) {
            return zero();
        }

        private JButton zero() {
            JButton b = new JButton();
            Dimension d = new Dimension(0, 0);
            b.setPreferredSize(d);
            b.setMinimumSize(d);
            b.setMaximumSize(d);
            return b;
        }

        @Override
        protected void paintTrack(Graphics g, JComponent c, Rectangle r) {
            g.setColor(PANEL);
            g.fillRect(r.x, r.y, r.width, r.height);
        }

        @Override
        protected void paintThumb(Graphics g, JComponent c, Rectangle r) {
            if (r.isEmpty()) return;
            Graphics2D g2 = aa(g);
            g2.setColor(isThumbRollover() ? mix(BORDER, Color.WHITE, 0.25) : BORDER);
            g2.fillRoundRect(r.x + 2, r.y + 2, r.width - 4, r.height - 4, 8, 8);
            g2.dispose();
        }
    }

    static JScrollPane scroll(JComponent view) {
        JScrollPane sp = new JScrollPane(view);
        sp.setBorder(null);
        sp.getVerticalScrollBar().setUI(new SlimScrollBarUI());
        sp.getVerticalScrollBar().setPreferredSize(new Dimension(12, 0));
        sp.getVerticalScrollBar().setUnitIncrement(16);
        sp.getHorizontalScrollBar().setUI(new SlimScrollBarUI());
        return sp;
    }

    /** Read-only text box in a rounded frame, with a fixed size. */
    static JComponent readOnlyBox(String text, int width, int height) {
        JTextArea area = new JTextArea(text);
        styleText(area);
        area.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 13));
        area.setEditable(false);
        area.setOpaque(false);
        area.setLineWrap(true);
        area.setWrapStyleWord(true);
        area.setCaretPosition(0);
        JScrollPane sp = scroll(area);
        sp.setOpaque(false);
        sp.getViewport().setOpaque(false);
        RoundedPanel box = new RoundedPanel(new BorderLayout(), FIELD, BORDER, 12);
        box.setBorder(new EmptyBorder(10, 12, 10, 6));
        box.add(sp, BorderLayout.CENTER);
        box.setPreferredSize(new Dimension(width, height));
        return box;
    }

    /**
     * Shows a styled modal dialog. The validator (may be null) returns an error
     * message to show inline, or null when the input is accepted.
     */
    static boolean dialog(Component parent, String title, String subtitle, JComponent body,
                          String okText, boolean danger, String cancelText, Supplier<String> validator) {
        return dialog(parent, title, subtitle, body, okText, danger, cancelText, validator, null, null);
    }

    /** Same as above with an optional third button that runs an action and closes the dialog. */
    static boolean dialog(Component parent, String title, String subtitle, JComponent body,
                          String okText, boolean danger, String cancelText, Supplier<String> validator,
                          String extraText, Runnable extraAction) {
        Window owner = parent == null ? null : SwingUtilities.getWindowAncestor(parent);
        JDialog d = new JDialog(owner, title, Dialog.ModalityType.APPLICATION_MODAL);
        d.setDefaultCloseOperation(JDialog.DISPOSE_ON_CLOSE);

        JPanel root = new JPanel(new BorderLayout(0, 16));
        root.setBackground(PANEL);
        root.setBorder(new EmptyBorder(24, 26, 20, 26));

        JPanel head = new JPanel();
        head.setOpaque(false);
        head.setLayout(new BoxLayout(head, BoxLayout.Y_AXIS));
        JLabel t = label(title, font(Font.BOLD, 20), TEXT);
        t.setAlignmentX(Component.LEFT_ALIGNMENT);
        head.add(t);
        if (subtitle != null) {
            head.add(Box.createVerticalStrut(4));
            JLabel s = label(subtitle, font(Font.PLAIN, 13), MUTED);
            s.setAlignmentX(Component.LEFT_ALIGNMENT);
            head.add(s);
        }

        JLabel err = label(" ", font(Font.PLAIN, 12), DANGER);
        JPanel buttons = new JPanel(new FlowLayout(FlowLayout.RIGHT, 8, 0));
        buttons.setOpaque(false);
        boolean[] result = {false};
        RoundedButton ok = new RoundedButton(okText, danger ? Kind.DANGER : Kind.PRIMARY);
        ok.addActionListener(e -> {
            String m = validator == null ? null : validator.get();
            if (m != null) {
                err.setText(m);
                return;
            }
            result[0] = true;
            d.dispose();
        });
        if (extraText != null) {
            buttons.add(button(extraText, Kind.GHOST, e -> {
                if (extraAction != null) extraAction.run();
                d.dispose();
            }));
        }
        if (cancelText != null) {
            buttons.add(button(cancelText, Kind.SECONDARY, e -> d.dispose()));
        }
        buttons.add(ok);

        JPanel south = new JPanel(new BorderLayout(0, 8));
        south.setOpaque(false);
        south.add(err, BorderLayout.NORTH);
        south.add(buttons, BorderLayout.SOUTH);

        root.add(head, BorderLayout.NORTH);
        root.add(body, BorderLayout.CENTER);
        root.add(south, BorderLayout.SOUTH);

        d.setIconImage(appIcon());
        d.setContentPane(root);
        d.getRootPane().setDefaultButton(ok);
        d.getRootPane().registerKeyboardAction(e -> d.dispose(),
                KeyStroke.getKeyStroke(KeyEvent.VK_ESCAPE, 0), JComponent.WHEN_IN_FOCUSED_WINDOW);
        d.setResizable(false);
        d.pack();
        d.setSize(Math.max(d.getWidth(), 460), d.getHeight());
        d.setLocationRelativeTo(parent);
        d.setVisible(true);
        return result[0];
    }

    static void message(Component parent, String title, String subtitle, JComponent body) {
        dialog(parent, title, subtitle, body, "OK", false, null, null);
    }

    // ------------------------------------------------------------------
    // Add / edit dialog
    // ------------------------------------------------------------------

    static Entry showEntryDialog(Component parent, Entry existing, int genLength) {
        JTextField site = new RoundedTextField(14);
        site.setText(existing == null ? "" : existing.site);
        JTextField category = new RoundedTextField(14);
        category.setText(existing == null ? "" : existing.category);
        JTextField user = new RoundedTextField(14);
        user.setText(existing == null ? "" : existing.username);
        JTextField url = new RoundedTextField(14);
        url.setText(existing == null ? "" : existing.url);
        JTextField totp = new RoundedTextField(24);
        totp.setText(existing == null ? "" : existing.totp);
        JPasswordField pw = new RoundedPasswordField(22);
        pw.setText(existing == null ? "" : existing.password);

        JTextArea notes = new JTextArea(existing == null ? "" : existing.notes, 2, 24);
        styleText(notes);
        notes.setOpaque(false);
        notes.setLineWrap(true);
        notes.setWrapStyleWord(true);
        JScrollPane notesScroll = scroll(notes);
        notesScroll.setOpaque(false);
        notesScroll.getViewport().setOpaque(false);
        RoundedPanel notesBox = new RoundedPanel(new BorderLayout(), FIELD, BORDER, 12);
        notesBox.setBorder(new EmptyBorder(8, 10, 8, 4));
        notesBox.add(notesScroll, BorderLayout.CENTER);

        char defaultEcho = pw.getEchoChar();
        RoundedButton show = new RoundedButton("Show", Kind.SECONDARY);
        show.addActionListener(e -> {
            boolean hidden = pw.getEchoChar() != 0;
            pw.setEchoChar(hidden ? (char) 0 : defaultEcho);
            show.setText(hidden ? "Hide" : "Show");
        });
        RoundedButton generate = new RoundedButton("Generate", Kind.SECONDARY);
        generate.addActionListener(e -> {
            pw.setText(generatePassword(genLength));
            pw.setEchoChar((char) 0);
            show.setText("Hide");
        });
        JPanel pwButtons = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 0));
        pwButtons.setOpaque(false);
        pwButtons.add(show);
        pwButtons.add(generate);
        JPanel pwRow = new JPanel(new BorderLayout(8, 0));
        pwRow.setOpaque(false);
        pwRow.add(pw, BorderLayout.CENTER);
        pwRow.add(pwButtons, BorderLayout.EAST);

        String[] names = {"Very weak", "Weak", "Fair", "Good", "Strong", "Excellent"};
        StrengthBar bar = new StrengthBar();
        JLabel strength = label(" ", font(Font.BOLD, 12), MUTED);
        strength.setPreferredSize(new Dimension(80, 20));
        Runnable update = () -> {
            String p = new String(pw.getPassword());
            if (p.isEmpty()) {
                bar.setScore(-1);
                strength.setText(" ");
                return;
            }
            int s = strengthScore(p);
            bar.setScore(s);
            strength.setText(names[s]);
        };
        pw.getDocument().addDocumentListener(onChange(update));
        update.run();
        JPanel strengthRow = new JPanel(new BorderLayout(10, 0));
        strengthRow.setOpaque(false);
        strengthRow.add(bar, BorderLayout.CENTER);
        strengthRow.add(strength, BorderLayout.EAST);

        JComponent body = column(
                pair(labeled("Site or app", site), labeled("Category", category)),
                pair(labeled("Username or email", user), labeled("Website address", url)),
                column(labeled("Password", pwRow), strengthRow),
                labeled("2FA secret key (optional, Base32)", totp),
                labeled("Notes", notesBox));

        Entry[] result = new Entry[1];
        boolean ok = dialog(parent, existing == null ? "Add entry" : "Edit entry",
                existing == null ? "Save a new login to your vault." : "Update this login.",
                body, "Save", false, "Cancel", () -> {
                    String s = site.getText().trim();
                    String p = new String(pw.getPassword());
                    String secret = totp.getText().replace(" ", "").toUpperCase();
                    if (s.isEmpty()) return "Please enter a site or app name.";
                    if (p.isEmpty()) return "Please enter a password.";
                    if (!secret.isEmpty()) {
                        try {
                            Totp.code(secret, System.currentTimeMillis());
                        } catch (Exception ex) {
                            return "The 2FA secret is not valid Base32.";
                        }
                    }
                    result[0] = new Entry(s, user.getText().trim(), p, notes.getText().trim(),
                            url.getText().trim(), category.getText().trim(), secret);
                    return null;
                });
        return ok ? result[0] : null;
    }

    // ------------------------------------------------------------------
    // Main window
    // ------------------------------------------------------------------

    static final class MainWindow extends JFrame {
        private final Vault vault;
        private final Runnable onLock;
        private final EntryTableModel model;
        private final JTable table;
        private final RoundedTextField search = new RoundedTextField(22);
        private final JLabel countLabel = label(" ", font(Font.PLAIN, 13), MUTED);
        private final JLabel status = label(" ", font(Font.PLAIN, 12), MUTED);
        private final JPopupMenu entryMenu = new JPopupMenu();
        private final JPopupMenu toolsMenu = new JPopupMenu();
        private final Timer idleTimer;
        private final Timer syncTimer;
        private boolean syncing;
        private final AWTEventListener activityListener;
        private Timer clipboardTimer;
        private Timer flashTimer;
        private boolean locked;
        private Entry lastDeleted;
        private int lastDeletedIndex;

        MainWindow(Vault vault, Runnable onLock) {
            super("Password Manager");
            setIconImage(appIcon());
            this.vault = vault;
            this.onLock = onLock;
            setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
            setSize(1100, 640);
            setMinimumSize(new Dimension(1020, 460));
            setLocationRelativeTo(null);

            JPanel root = new JPanel(new BorderLayout());
            root.setBackground(BG);
            setContentPane(root);

            model = new EntryTableModel(vault);
            table = buildTable();

            TableRowSorter<EntryTableModel> sorter = new TableRowSorter<>(model);
            table.setRowSorter(sorter);
            search.placeholder = "Search entries\u2026";
            search.getDocument().addDocumentListener(onChange(() -> {
                String t = search.getText().trim();
                sorter.setRowFilter(t.isEmpty() ? null
                        : RowFilter.regexFilter("(?i)" + Pattern.quote(t), 0, 1, 3, 4));
            }));

            // Menus
            entryMenu.add(menuItem("Show / hide password", e -> toggleReveal()));
            entryMenu.add(menuItem("Open website", e -> openSite()));
            entryMenu.addSeparator();
            entryMenu.add(menuItem("Auto-type login (username + password)", e -> autoType("login")));
            entryMenu.add(menuItem("Auto-type password only", e -> autoType("password")));
            entryMenu.add(menuItem("Auto-type 2FA code", e -> autoType("totp")));
            entryMenu.addSeparator();
            entryMenu.add(menuItem("2FA code\u2026", e -> showTotp()));
            entryMenu.add(menuItem("Password history\u2026", e -> showHistory()));
            entryMenu.add(menuItem("Check for data breaches\u2026", e -> checkBreach()));

            toolsMenu.add(menuItem("Security audit\u2026", e -> showAudit()));
            toolsMenu.addSeparator();
            toolsMenu.add(menuItem("Import from CSV or passwords.txt\u2026", e -> importFile()));
            toolsMenu.add(menuItem("Export to CSV\u2026", e -> exportFile()));
            toolsMenu.addSeparator();
            toolsMenu.add(menuItem("Change master password\u2026", e -> changeMasterPassword()));
            toolsMenu.add(menuItem("Settings\u2026", e -> showSettings()));
            toolsMenu.add(menuItem("Vault location and sync\u2026", e -> showLocation()));
            toolsMenu.addSeparator();
            toolsMenu.add(menuItem("Undo last delete  (Ctrl+Z)", e -> undoDelete()));

            // Header: brand + search
            JPanel titles = new JPanel(new GridLayout(2, 1));
            titles.setOpaque(false);
            titles.add(label("Password Manager", font(Font.BOLD, 20), TEXT));
            titles.add(countLabel);
            JPanel brand = new JPanel(new BorderLayout(14, 0));
            brand.setOpaque(false);
            brand.add(new Logo(44), BorderLayout.WEST);
            brand.add(titles, BorderLayout.CENTER);

            search.setPreferredSize(new Dimension(280, search.getPreferredSize().height));
            JPanel searchWrap = new JPanel(new GridBagLayout());
            searchWrap.setOpaque(false);
            searchWrap.add(search);

            JPanel header = new JPanel(new BorderLayout(14, 0));
            header.setOpaque(false);
            header.setBorder(new EmptyBorder(20, 24, 12, 24));
            header.add(brand, BorderLayout.WEST);
            header.add(searchWrap, BorderLayout.EAST);

            // Action bar
            JPanel left = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 0));
            left.setOpaque(false);
            left.add(button("+  Add", Kind.PRIMARY, e -> addEntry()));
            left.add(button("Edit", Kind.SECONDARY, e -> editSelected()));
            RoundedButton delete = button("Delete", Kind.SECONDARY, e -> deleteSelected());
            delete.setForeground(DANGER);
            left.add(delete);

            JPanel right = new JPanel(new FlowLayout(FlowLayout.RIGHT, 8, 0));
            right.setOpaque(false);
            right.add(button("Copy Password", Kind.SECONDARY, e -> copySelected(true)));
            right.add(button("Copy Username", Kind.SECONDARY, e -> copySelected(false)));
            right.add(button("Auto-type", Kind.SECONDARY, e -> autoType("login")));
            RoundedButton more = new RoundedButton("More \u25BE", Kind.SECONDARY);
            more.addActionListener(e -> {
                if (selectedModelRow() >= 0) entryMenu.show(more, 0, more.getHeight() + 4);
            });
            right.add(more);
            RoundedButton tools = new RoundedButton("Tools \u25BE", Kind.SECONDARY);
            tools.addActionListener(e -> toolsMenu.show(tools, 0, tools.getHeight() + 4));
            right.add(tools);
            right.add(button("Lock", Kind.GHOST, e -> lockVault()));

            JPanel actions = new JPanel(new BorderLayout());
            actions.setOpaque(false);
            actions.setBorder(new EmptyBorder(0, 24, 14, 24));
            actions.add(left, BorderLayout.WEST);
            actions.add(right, BorderLayout.EAST);

            JPanel north = new JPanel(new BorderLayout());
            north.setOpaque(false);
            north.add(header, BorderLayout.NORTH);
            north.add(actions, BorderLayout.SOUTH);

            // Table card
            JScrollPane sp = scroll(table);
            sp.getViewport().setBackground(PANEL);
            sp.setBorder(BorderFactory.createLineBorder(BORDER));
            JPanel center = new JPanel(new BorderLayout());
            center.setOpaque(false);
            center.setBorder(new EmptyBorder(0, 24, 0, 24));
            center.add(sp, BorderLayout.CENTER);

            status.setBorder(new EmptyBorder(10, 26, 14, 26));

            root.add(north, BorderLayout.NORTH);
            root.add(center, BorderLayout.CENTER);
            root.add(status, BorderLayout.SOUTH);
            updateCount();
            status.setText(defaultStatus());

            bind("control N", "addEntry", this::addEntry);
            bind("control F", "focusSearch", () -> search.requestFocusInWindow());
            bind("control L", "lockVault", this::lockVault);
            bind("control Z", "undoDelete", this::undoDelete);
            bind("control T", "autoType", () -> autoType("login"));

            // Auto-lock after inactivity
            idleTimer = new Timer(vault.idleMinutes * 60 * 1000, e -> lockVault());
            idleTimer.setRepeats(false);
            idleTimer.start();
            activityListener = ev -> idleTimer.restart();
            Toolkit.getDefaultToolkit().addAWTEventListener(activityListener,
                    AWTEvent.MOUSE_EVENT_MASK | AWTEvent.MOUSE_MOTION_EVENT_MASK | AWTEvent.KEY_EVENT_MASK);

            // Pick up changes made on other computers (cloud-folder sync)
            syncTimer = new Timer(SYNC_CHECK_MS, e -> checkExternalChanges());
            syncTimer.start();
        }

        private void bind(String keystroke, String name, Runnable r) {
            getRootPane().getInputMap(JComponent.WHEN_IN_FOCUSED_WINDOW).put(KeyStroke.getKeyStroke(keystroke), name);
            getRootPane().getActionMap().put(name, new AbstractAction() {
                @Override
                public void actionPerformed(ActionEvent e) {
                    r.run();
                }
            });
        }

        private JTable buildTable() {
            JTable t = new JTable(model) {
                @Override
                protected void paintComponent(Graphics g) {
                    super.paintComponent(g);
                    if (getRowCount() == 0) {
                        Graphics2D g2 = aa(g);
                        g2.setFont(font(Font.PLAIN, 14));
                        g2.setColor(MUTED);
                        String msg = MainWindow.this.vault.entries.isEmpty()
                                ? "No entries yet. Click \"Add\" to save your first login."
                                : "No entries match your search.";
                        FontMetrics fm = g2.getFontMetrics();
                        g2.drawString(msg, (getWidth() - fm.stringWidth(msg)) / 2, getHeight() / 2);
                        g2.dispose();
                    }
                }
            };
            t.setRowHeight(46);
            t.setFillsViewportHeight(true);
            t.setShowGrid(false);
            t.setIntercellSpacing(new Dimension(0, 0));
            t.setBackground(PANEL);
            t.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
            t.setDefaultRenderer(Object.class, new CellRenderer());
            t.getColumnModel().getColumn(0).setPreferredWidth(200);
            t.getColumnModel().getColumn(1).setPreferredWidth(200);
            t.getColumnModel().getColumn(2).setPreferredWidth(130);
            t.getColumnModel().getColumn(3).setPreferredWidth(110);
            t.getColumnModel().getColumn(4).setPreferredWidth(210);

            JTableHeader h = t.getTableHeader();
            h.setReorderingAllowed(false);
            h.setPreferredSize(new Dimension(0, 36));
            h.setDefaultRenderer(new DefaultTableCellRenderer() {
                @Override
                public Component getTableCellRendererComponent(JTable tb, Object v, boolean s, boolean f, int r, int c) {
                    String text = v == null ? "" : v.toString().toUpperCase();
                    for (RowSorter.SortKey k : tb.getRowSorter().getSortKeys()) {
                        if (k.getColumn() == c) {
                            text += k.getSortOrder() == SortOrder.ASCENDING ? "  \u25B2" : "  \u25BC";
                        }
                    }
                    JLabel l = (JLabel) super.getTableCellRendererComponent(tb, text, false, false, r, c);
                    l.setOpaque(true);
                    l.setBackground(CARD);
                    l.setForeground(MUTED);
                    l.setFont(font(Font.BOLD, 11));
                    l.setHorizontalAlignment(SwingConstants.LEFT);
                    l.setBorder(BorderFactory.createCompoundBorder(
                            BorderFactory.createMatteBorder(0, 0, 1, 0, BORDER),
                            new EmptyBorder(0, c == 0 ? 58 : 14, 0, 10)));
                    return l;
                }
            });

            t.addMouseListener(new MouseAdapter() {
                @Override
                public void mouseClicked(MouseEvent e) {
                    if (e.getClickCount() == 2 && SwingUtilities.isLeftMouseButton(e)) {
                        editSelected();
                    }
                }

                @Override
                public void mousePressed(MouseEvent e) {
                    popup(e);
                }

                @Override
                public void mouseReleased(MouseEvent e) {
                    popup(e);
                }

                private void popup(MouseEvent e) {
                    if (e.isPopupTrigger()) {
                        int r = t.rowAtPoint(e.getPoint());
                        if (r >= 0) {
                            t.setRowSelectionInterval(r, r);
                            entryMenu.show(t, e.getX(), e.getY());
                        }
                    }
                }
            });
            t.getInputMap(JComponent.WHEN_FOCUSED)
                    .put(KeyStroke.getKeyStroke(KeyEvent.VK_DELETE, 0), "deleteEntry");
            t.getActionMap().put("deleteEntry", new AbstractAction() {
                @Override
                public void actionPerformed(ActionEvent e) {
                    deleteSelected();
                }
            });
            return t;
        }

        // ---- helpers ---------------------------------------------------

        private String defaultStatus() {
            return "AES-256-GCM encrypted  \u2022  auto-lock after " + vault.idleMinutes + " min";
        }

        private void updateCount() {
            int n = vault.entries.size();
            countLabel.setText(n + (n == 1 ? " saved login" : " saved logins"));
        }

        private void flash(String message) {
            status.setText(message);
            if (flashTimer != null) {
                flashTimer.stop();
            }
            flashTimer = new Timer(5000, e -> status.setText(defaultStatus()));
            flashTimer.setRepeats(false);
            flashTimer.start();
        }

        private int selectedModelRow() {
            int viewRow = table.getSelectedRow();
            if (viewRow < 0) {
                flash("Select an entry first.");
                return -1;
            }
            return table.convertRowIndexToModel(viewRow);
        }

        private Entry selectedEntry() {
            int row = selectedModelRow();
            return row < 0 ? null : vault.entries.get(row);
        }

        private boolean persist() {
            if (locked) {
                return false;
            }
            try {
                SaveStatus result = vault.save(true);
                if (result == SaveStatus.MERGED) {
                    refreshAll();
                    flash("Merged with changes made on another device.");
                } else if (result == SaveStatus.CONFLICT_COPY) {
                    String where = String.valueOf(vault.conflictCopy == null ? "" : vault.conflictCopy.getFileName());
                    message(this, "Saved to a separate file",
                            "The vault was changed elsewhere with a different master password.",
                            textBlock("Your changes were NOT written over the other version. They were saved "
                                    + "(encrypted with your previous master password) to:\n" + where
                                    + "\n\nThe vault will now lock. Unlock it again with the newest master password. "
                                    + "To recover the saved changes, use \"Open existing vault\" on that file.", 420, TEXT));
                    lockVault();
                    return false;
                }
                return true;
            } catch (Exception ex) {
                message(this, "Save error", "Your changes could not be saved.",
                        textBlock(String.valueOf(ex.getMessage()), 380, TEXT));
                return false;
            }
        }

        private void checkExternalChanges() {
            if (locked || syncing) return;
            syncing = true;
            try {
                switch (vault.syncFromDisk()) {
                    case MERGED:
                        refreshAll();
                        flash("Vault updated from another device.");
                        break;
                    case NEEDS_RELOCK:
                        message(this, "Vault changed on another device",
                                "The master password was changed elsewhere.",
                                textBlock("Please unlock the vault again with the new master password.", 380, TEXT));
                        lockVault();
                        break;
                    default:
                        break;
                }
            } catch (Exception ignored) {
                // try again on the next tick
            } finally {
                syncing = false;
            }
        }

        private void refreshAll() {
            model.fireTableDataChanged();
            updateCount();
        }

        // ---- entry actions ---------------------------------------------

        private void addEntry() {
            Entry e = showEntryDialog(this, null, vault.genLength);
            if (e != null && !locked) {
                vault.entries.add(e);
                persist();
                refreshAll();
                flash("Entry saved.");
            }
        }

        private void editSelected() {
            Entry current = selectedEntry();
            if (current == null) return;
            Entry updated = showEntryDialog(this, current, vault.genLength);
            if (updated != null && !locked) {
                if (vault.entries.contains(current)) {
                    current.applyEdit(updated);
                } else {
                    vault.entries.add(updated); // it was deleted on another device meanwhile: keep this edit
                }
                persist();
                int idx = vault.entries.indexOf(current);
                if (idx >= 0) {
                    model.fireTableRowsUpdated(idx, idx);
                } else {
                    refreshAll();
                }
                flash("Entry updated.");
            }
        }

        private void deleteSelected() {
            Entry e = selectedEntry();
            if (e == null) return;
            boolean yes = dialog(this, "Delete entry?",
                    "\"" + e.site + "\" will be removed.",
                    label("You can undo this with Ctrl+Z until you lock the vault.", font(Font.PLAIN, 13), MUTED),
                    "Delete", true, "Cancel", null);
            if (yes && !locked) {
                int idx = vault.entries.indexOf(e);
                if (idx < 0) return; // already removed by a sync
                vault.entries.remove(e);
                vault.recordDeletion(e);
                lastDeleted = e;
                lastDeletedIndex = idx;
                persist();
                refreshAll();
                flash("Entry deleted. Press Ctrl+Z to undo.");
            }
        }

        private void undoDelete() {
            if (lastDeleted == null) {
                flash("Nothing to undo.");
                return;
            }
            vault.entries.add(Math.min(lastDeletedIndex, vault.entries.size()), lastDeleted);
            vault.restore(lastDeleted);
            String name = lastDeleted.site;
            lastDeleted = null;
            persist();
            refreshAll();
            flash("Restored \"" + name + "\".");
        }

        // ---- auto-type -------------------------------------------------------

        private void autoType(String mode) {
            Entry e = selectedEntry();
            if (e == null) return;
            if (mode.equals("totp") && e.totp.isEmpty()) {
                flash("No 2FA secret saved for this entry. Edit it to add one.");
                return;
            }
            int delay = vault.autoTypeDelay;
            boolean enter = vault.autoTypeEnter;
            flash("Typing into your previous window in " + delay + " seconds. Click the right field now.");
            setExtendedState(Frame.ICONIFIED);
            Timer t = new Timer(delay * 1000, ev -> {
                if (locked) return;
                List<String> seq;
                try {
                    seq = autoTypeSequence(e, mode, enter, System.currentTimeMillis());
                } catch (Exception ex) {
                    setExtendedState(Frame.NORMAL);
                    flash("Auto-type failed: " + ex.getMessage());
                    return;
                }
                Thread worker = new Thread(() -> {
                    String error = null;
                    try {
                        typeSequence(seq);
                    } catch (Exception ex) {
                        error = String.valueOf(ex.getMessage());
                    }
                    String msg = error == null ? "Auto-typed into your previous window."
                            : "Auto-type failed: " + error;
                    boolean failed = error != null;
                    SwingUtilities.invokeLater(() -> {
                        if (failed) {
                            setExtendedState(Frame.NORMAL);
                        }
                        flash(msg);
                    });
                }, "auto-type");
                worker.setDaemon(true);
                worker.start();
            });
            t.setRepeats(false);
            t.start();
        }

        private void toggleReveal() {
            int row = selectedModelRow();
            if (row < 0) return;
            Entry e = vault.entries.get(row);
            e.revealed = !e.revealed;
            model.fireTableRowsUpdated(row, row);
        }

        private void copySelected(boolean password) {
            Entry e = selectedEntry();
            if (e == null) return;
            copy(password ? e.password : e.username, password ? "Password" : "Username");
        }

        private void copy(String text, String what) {
            Clipboard cb = Toolkit.getDefaultToolkit().getSystemClipboard();
            cb.setContents(new StringSelection(text), null);
            if (clipboardTimer != null) {
                clipboardTimer.stop();
            }
            clipboardTimer = new Timer(vault.clipboardSeconds * 1000, ev -> {
                try {
                    if (text.equals(cb.getData(DataFlavor.stringFlavor))) {
                        cb.setContents(new StringSelection(""), null);
                    }
                } catch (Exception ignored) {
                    // clipboard unavailable or holds something else
                }
            });
            clipboardTimer.setRepeats(false);
            clipboardTimer.start();
            flash(what + " copied. Clipboard clears in " + vault.clipboardSeconds + " seconds.");
        }

        private void openSite() {
            Entry e = selectedEntry();
            if (e == null) return;
            String u = e.url.trim();
            if (u.isEmpty()) {
                flash("This entry has no website address. Edit it to add one.");
                return;
            }
            if (!u.matches("(?i)^[a-z][a-z0-9+.-]*://.*")) {
                u = "https://" + u;
            }
            String lower = u.toLowerCase();
            if (!lower.startsWith("http://") && !lower.startsWith("https://")) {
                flash("Only http and https links can be opened.");
                return;
            }
            try {
                if (!Desktop.isDesktopSupported() || !Desktop.getDesktop().isSupported(Desktop.Action.BROWSE)) {
                    throw new UnsupportedOperationException("opening a browser is not supported here");
                }
                Desktop.getDesktop().browse(URI.create(u));
                flash("Opened " + u);
            } catch (Exception ex) {
                flash("Could not open the website: " + ex.getMessage());
            }
        }

        // ---- 2FA ---------------------------------------------------------

        private void showTotp() {
            Entry entry = selectedEntry();
            if (entry == null) return;
            if (entry.totp.isEmpty()) {
                flash("No 2FA secret saved for this entry. Edit it to add one.");
                return;
            }
            JLabel code = label(" ", new Font(Font.MONOSPACED, Font.BOLD, 40), TEXT);
            JLabel seconds = label(" ", font(Font.BOLD, 13), MUTED);
            ProgressLine line = new ProgressLine();
            String[] current = {""};
            Runnable upd = () -> {
                try {
                    long now = System.currentTimeMillis();
                    current[0] = Totp.code(entry.totp, now);
                    code.setText(current[0].substring(0, 3) + " " + current[0].substring(3));
                    long remain = 30 - (now / 1000) % 30;
                    seconds.setText("Refreshes in " + remain + "s");
                    line.setFraction(remain / 30.0);
                } catch (Exception ex) {
                    current[0] = "";
                    code.setText("Invalid key");
                    seconds.setText("The saved 2FA secret is not valid.");
                }
            };
            JPanel codeRow = new JPanel(new FlowLayout(FlowLayout.CENTER, 0, 0));
            codeRow.setOpaque(false);
            codeRow.add(code);
            JPanel secRow = new JPanel(new FlowLayout(FlowLayout.CENTER, 0, 0));
            secRow.setOpaque(false);
            secRow.add(seconds);
            JComponent body = column(codeRow, line, secRow);

            upd.run();
            Timer t = new Timer(500, ev -> upd.run());
            t.start();
            boolean copyIt = dialog(this, "2FA code", entry.site, body, "Copy Code", false, "Close", null);
            t.stop();
            if (copyIt && !current[0].isEmpty() && !locked) {
                copy(current[0], "2FA code");
            }
        }

        // ---- history -------------------------------------------------------

        private void showHistory() {
            Entry e = selectedEntry();
            if (e == null) return;
            StringBuilder sb = new StringBuilder();
            sb.append("Current   set ").append(formatTime(e.updated)).append('\n');
            sb.append("          ").append(e.password).append("\n\n");
            if (e.history.isEmpty()) {
                sb.append("No previous passwords yet. Changing this entry's\npassword will keep the old one here.");
            } else {
                for (HistoryItem h : e.history) {
                    sb.append("Previous  set ").append(formatTime(h.when)).append('\n');
                    sb.append("          ").append(h.password).append("\n\n");
                }
            }
            message(this, "Password history", e.site, readOnlyBox(sb.toString(), 440, 240));
        }

        // ---- security tools --------------------------------------------------

        private void showAudit() {
            AuditResult r = audit(vault.entries, System.currentTimeMillis());
            Color c = r.percent() >= 80 ? GOOD : r.percent() >= 50 ? WARN : DANGER;
            JLabel pct = label(r.percent() + "%", font(Font.BOLD, 44), c);
            JLabel cap = label(r.healthy + " of " + r.total + " logins have no issues", font(Font.PLAIN, 13), MUTED);
            JLabel sub = label("Checks: weak, reused, and older than " + OLD_PASSWORD_DAYS + " days",
                    font(Font.PLAIN, 12), MUTED);
            JPanel texts = new JPanel(new GridLayout(2, 1, 0, 2));
            texts.setOpaque(false);
            texts.add(cap);
            texts.add(sub);
            JPanel top = new JPanel(new BorderLayout(16, 0));
            top.setOpaque(false);
            top.add(pct, BorderLayout.WEST);
            top.add(texts, BorderLayout.CENTER);

            String list = r.lines.isEmpty()
                    ? (r.total == 0 ? "Add some logins to run an audit." : "No problems found. Nice work!")
                    : String.join("\n", r.lines);
            message(this, "Security audit", "A quick health check of your vault.",
                    column(top, readOnlyBox(list, 480, 200)));
        }

        private void checkBreach() {
            Entry e = selectedEntry();
            if (e == null) return;
            String pw = e.password;
            String site = e.site;
            flash("Checking Have I Been Pwned\u2026 (only a partial hash is sent)");
            new SwingWorker<Long, Void>() {
                @Override
                protected Long doInBackground() throws Exception {
                    return pwnedCount(pw);
                }

                @Override
                protected void done() {
                    if (locked) return;
                    try {
                        long n = get();
                        if (n > 0) {
                            dialog(MainWindow.this, "Password found in breaches", site,
                                    textBlock("This password appeared " + String.format("%,d", n)
                                            + " times in known data breaches. Change it now and never reuse it.",
                                            380, TEXT), "OK", true, null, null);
                        } else {
                            message(MainWindow.this, "No breaches found", site,
                                    textBlock("This password was not found in known breach data.", 380, TEXT));
                        }
                        status.setText(defaultStatus());
                    } catch (Exception ex) {
                        flash("Breach check failed. Are you online?");
                    }
                }
            }.execute();
        }

        private void changeMasterPassword() {
            JPasswordField cur = new RoundedPasswordField(24);
            JPasswordField n1 = new RoundedPasswordField(24);
            JPasswordField n2 = new RoundedPasswordField(24);
            JComponent body = column(labeled("Current master password", cur),
                    labeled("New master password (min " + MIN_MASTER_LENGTH + " characters)", n1),
                    labeled("Confirm new master password", n2));
            boolean ok = dialog(this, "Change master password",
                    "Your vault will be re-encrypted with a new key.", body, "Change Password", false, "Cancel", () -> {
                        char[] c = cur.getPassword();
                        char[] a = n1.getPassword();
                        char[] b = n2.getPassword();
                        try {
                            if (!vault.verify(c)) return "Current master password is incorrect.";
                            if (a.length < MIN_MASTER_LENGTH) {
                                return "New password must be at least " + MIN_MASTER_LENGTH + " characters.";
                            }
                            if (!Arrays.equals(a, b)) return "The new passwords do not match.";
                            vault.changeMasterPassword(a);
                            return null;
                        } catch (Exception ex) {
                            return "Could not change password: " + ex.getMessage();
                        } finally {
                            Arrays.fill(c, '\0');
                            Arrays.fill(a, '\0');
                            Arrays.fill(b, '\0');
                        }
                    });
            if (ok) {
                flash("Master password changed. Your old backup file was removed.");
            }
        }

        private void showSettings() {
            JTextField idle = new RoundedTextField(8);
            idle.setText(String.valueOf(vault.idleMinutes));
            JTextField clip = new RoundedTextField(8);
            clip.setText(String.valueOf(vault.clipboardSeconds));
            JTextField gen = new RoundedTextField(8);
            gen.setText(String.valueOf(vault.genLength));
            JTextField typeDelay = new RoundedTextField(8);
            typeDelay.setText(String.valueOf(vault.autoTypeDelay));
            boolean[] enterOn = {vault.autoTypeEnter};
            RoundedButton enterBtn = new RoundedButton(enterOn[0] ? "On" : "Off", Kind.SECONDARY);
            enterBtn.addActionListener(e -> {
                enterOn[0] = !enterOn[0];
                enterBtn.setText(enterOn[0] ? "On" : "Off");
            });
            JPanel enterRow = new JPanel(new FlowLayout(FlowLayout.LEFT, 0, 0));
            enterRow.setOpaque(false);
            enterRow.add(enterBtn);
            JComponent body = column(
                    pair(labeled("Auto-lock (minutes, 1-120)", idle), labeled("Clipboard clear (seconds, 5-300)", clip)),
                    pair(labeled("Generated password length (8-64)", gen),
                            labeled("Auto-type delay (seconds, 1-10)", typeDelay)),
                    labeled("Press Enter after auto-typing", enterRow));
            boolean ok = dialog(this, "Settings", "Saved inside your encrypted vault.", body,
                    "Save", false, "Cancel", () -> {
                        try {
                            int i = Integer.parseInt(idle.getText().trim());
                            int c = Integer.parseInt(clip.getText().trim());
                            int g = Integer.parseInt(gen.getText().trim());
                            int d = Integer.parseInt(typeDelay.getText().trim());
                            if (i < 1 || i > 120) return "Auto-lock must be between 1 and 120 minutes.";
                            if (c < 5 || c > 300) return "Clipboard timer must be between 5 and 300 seconds.";
                            if (g < 8 || g > 64) return "Password length must be between 8 and 64.";
                            if (d < 1 || d > 10) return "Auto-type delay must be between 1 and 10 seconds.";
                            vault.idleMinutes = i;
                            vault.clipboardSeconds = c;
                            vault.genLength = g;
                            vault.autoTypeDelay = d;
                            vault.autoTypeEnter = enterOn[0];
                            return null;
                        } catch (NumberFormatException ex) {
                            return "Please enter whole numbers only.";
                        }
                    });
            if (ok && !locked) {
                idleTimer.setInitialDelay(vault.idleMinutes * 60 * 1000);
                idleTimer.restart();
                persist();
                flash("Settings saved.");
            }
        }

        private void showLocation() {
            JComponent body = column(
                    labeled("Current vault file", readOnlyBox(vault.path().toAbsolutePath().toString(), 500, 64)),
                    textBlock("To use the same vault on several computers, move it into a folder that Dropbox, "
                            + "OneDrive, Google Drive or a similar service keeps in sync. On each other computer "
                            + "start the app, choose \"Open existing vault\" and pick that file.", 500, MUTED),
                    textBlock("Changes made on different computers are merged automatically (the newest edit to "
                            + "each entry wins). The file stays encrypted, so the sync service never sees your "
                            + "passwords. Let the sync finish before switching computers.", 500, MUTED));
            boolean move = dialog(this, "Vault location and sync", "Sync through a cloud folder.", body,
                    "Move vault\u2026", false, "Close", null);
            if (!move || locked) return;
            JFileChooser fc = new JFileChooser();
            fc.setDialogTitle("Choose the folder for your vault");
            fc.setFileSelectionMode(JFileChooser.DIRECTORIES_ONLY);
            if (fc.showOpenDialog(this) != JFileChooser.APPROVE_OPTION || locked) return;
            Path target = fc.getSelectedFile().toPath().toAbsolutePath().resolve("vault.dat");
            Path old = null;
            try {
                old = vault.moveTo(target);
                saveVaultPath(target);
                vaultPath = target;
                Vault.deleteVaultFiles(old);
                flash("Vault moved to " + target);
            } catch (Exception ex) {
                if (old != null) { // roll back so the app keeps using the old file
                    vault.setPath(old);
                    try {
                        Files.deleteIfExists(target);
                    } catch (IOException ignored) {
                        // nothing more we can do
                    }
                }
                message(this, "Could not move vault", "Nothing was changed.",
                        textBlock(String.valueOf(ex.getMessage()), 380, TEXT));
            }
        }

        // ---- import / export -----------------------------------------------

        private void importFile() {
            JFileChooser fc = new JFileChooser();
            fc.setDialogTitle("Import passwords (CSV or passwords.txt)");
            if (fc.showOpenDialog(this) != JFileChooser.APPROVE_OPTION || locked) return;
            File f = fc.getSelectedFile();
            try {
                String text = Files.readString(f.toPath(), StandardCharsets.UTF_8);
                List<Entry> imported = f.getName().toLowerCase().endsWith(".txt")
                        ? parseColonList(text) : parseCsvEntries(text);
                int added = 0;
                int skipped = 0;
                for (Entry n : imported) {
                    if (isDuplicate(n)) {
                        skipped++;
                    } else {
                        vault.entries.add(n);
                        added++;
                    }
                }
                if (added > 0) persist();
                refreshAll();
                flash("Imported " + added + " entries" + (skipped > 0 ? " (" + skipped + " duplicates skipped)" : "") + ".");
            } catch (Exception ex) {
                message(this, "Import failed", "Nothing was imported.",
                        textBlock(String.valueOf(ex.getMessage()), 380, TEXT));
            }
        }

        private boolean isDuplicate(Entry n) {
            for (Entry e : vault.entries) {
                if (e.site.equalsIgnoreCase(n.site) && e.username.equals(n.username) && e.password.equals(n.password)) {
                    return true;
                }
            }
            return false;
        }

        private void exportFile() {
            if (vault.entries.isEmpty()) {
                flash("There is nothing to export yet.");
                return;
            }
            boolean sure = dialog(this, "Export unencrypted CSV?",
                    "The file will contain all your passwords in plain text.",
                    textBlock("Anyone who opens the file can read every password. Store it somewhere safe and "
                            + "delete it as soon as you are done.", 400, MUTED),
                    "Export", true, "Cancel", null);
            if (!sure || locked) return;
            JFileChooser fc = new JFileChooser();
            fc.setDialogTitle("Export passwords to CSV");
            fc.setSelectedFile(new File("passwords-export.csv"));
            if (fc.showSaveDialog(this) != JFileChooser.APPROVE_OPTION || locked) return;
            File f = fc.getSelectedFile();
            if (f.exists() && !dialog(this, "Replace existing file?", f.getName() + " already exists.",
                    label("It will be overwritten.", font(Font.PLAIN, 13), MUTED), "Replace", true, "Cancel", null)) {
                return;
            }
            try {
                Files.writeString(f.toPath(), toCsv(vault.entries), StandardCharsets.UTF_8);
                flash("Exported " + vault.entries.size() + " entries to " + f.getName() + ".");
            } catch (Exception ex) {
                message(this, "Export failed", null, textBlock(String.valueOf(ex.getMessage()), 380, TEXT));
            }
        }

        // ---- lock --------------------------------------------------------------

        private void lockVault() {
            if (locked) return;
            locked = true;
            idleTimer.stop();
            syncTimer.stop();
            Toolkit.getDefaultToolkit().removeAWTEventListener(activityListener);
            lastDeleted = null;
            vault.lock();
            dispose();
            onLock.run();
        }
    }

    // ------------------------------------------------------------------
    // Table model + renderer (passwords masked unless the row is revealed)
    // ------------------------------------------------------------------

    static final class EntryTableModel extends AbstractTableModel {
        private static final String[] COLUMNS = {"Site", "Username", "Password", "Category", "Notes"};
        private final Vault vault;

        EntryTableModel(Vault vault) {
            this.vault = vault;
        }

        @Override
        public int getRowCount() {
            return vault.entries.size();
        }

        @Override
        public int getColumnCount() {
            return COLUMNS.length;
        }

        @Override
        public String getColumnName(int c) {
            return COLUMNS[c];
        }

        @Override
        public Object getValueAt(int row, int col) {
            if (row >= vault.entries.size()) return "";
            Entry e = vault.entries.get(row);
            switch (col) {
                case 0: return e.site;
                case 1: return e.username;
                case 2: return e.revealed ? e.password : MASK;
                case 3: return e.category;
                default: return e.notes.replace('\n', ' ');
            }
        }
    }

    static final class CellRenderer extends DefaultTableCellRenderer {
        private String avatar;
        private Color avatarColor = ACCENT;

        @Override
        public Component getTableCellRendererComponent(JTable t, Object v, boolean sel, boolean focus, int row, int col) {
            super.getTableCellRendererComponent(t, v, false, false, row, col);
            setOpaque(true);
            setBackground(sel ? SELECT : (row % 2 == 0 ? PANEL : ROW_ALT));
            setForeground(col >= 3 ? MUTED : TEXT);
            setFont(font(col == 0 ? Font.BOLD : Font.PLAIN, 14));
            setBorder(new EmptyBorder(0, col == 0 ? 58 : 14, 0, 10));
            avatar = null;
            if (col == 0) {
                String s = String.valueOf(v);
                avatar = s.isEmpty() ? "?" : s.substring(0, 1).toUpperCase();
                avatarColor = AVATARS[Math.floorMod(s.toLowerCase().hashCode(), AVATARS.length)];
            }
            if (col == 2) {
                boolean masked = MASK.equals(v);
                setFont(new Font(Font.MONOSPACED, Font.PLAIN, 14));
                setForeground(masked ? MUTED : TEXT);
            }
            return this;
        }

        @Override
        protected void paintComponent(Graphics g) {
            super.paintComponent(g);
            if (avatar != null) {
                Graphics2D g2 = aa(g);
                int d = 30;
                int y = (getHeight() - d) / 2;
                g2.setColor(avatarColor);
                g2.fillOval(14, y, d, d);
                g2.setColor(Color.WHITE);
                g2.setFont(font(Font.BOLD, 14));
                FontMetrics fm = g2.getFontMetrics();
                g2.drawString(avatar, 14 + (d - fm.stringWidth(avatar)) / 2,
                        y + (d + fm.getAscent() - fm.getDescent()) / 2);
                g2.dispose();
            }
        }
    }
}
