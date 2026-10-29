import javax.crypto.*;
import javax.crypto.spec.*;
import java.io.*;
import java.nio.file.*;
import java.security.*;
import java.util.*;

public class ManagerTests {
    static int fails = 0;
    static void check(String name, boolean ok) { System.out.println((ok ? "PASS " : "FAIL ") + name); if (!ok) fails++; }

    public static void main(String[] a) throws Exception {
        // TOTP RFC 6238 vectors (SHA1, secret "12345678901234567890")
        String secret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";
        check("TOTP t=59 -> 287082", PasswordManager.Totp.code(secret, 59_000L).equals("287082"));
        check("TOTP t=1111111109 -> 081804", PasswordManager.Totp.code(secret, 1111111109_000L).equals("081804"));
        check("TOTP t=1234567890 -> 005924", PasswordManager.Totp.code(secret, 1234567890_000L).equals("005924"));
        boolean bad = false; try { PasswordManager.Totp.code("not*base32", 0); } catch (IllegalArgumentException e) { bad = true; }
        check("TOTP rejects invalid base32", bad);

        // Vault v2 roundtrip + settings + history
        Path p = Paths.get("t.dat"); Files.deleteIfExists(p);
        char[] pw = "correct horse battery".toCharArray();
        PasswordManager.Vault v = PasswordManager.Vault.create(p, pw);
        PasswordManager.Entry e = new PasswordManager.Entry("GitHub", "me", "Old#Pass123xyzQ", "n", "github.com", "Work", secret);
        v.entries.add(e);
        PasswordManager.Entry upd = new PasswordManager.Entry("GitHub", "me", "New#Pass456abcR", "n", "github.com", "Work", secret);
        e.applyEdit(upd);
        check("history records old password", e.history.size() == 1 && e.history.get(0).password.equals("Old#Pass123xyzQ"));
        v.idleMinutes = 9; v.clipboardSeconds = 45; v.genLength = 24;
        v.save(true);
        PasswordManager.Vault r = PasswordManager.Vault.open(p, pw);
        check("roundtrip entry fields", r.entries.size() == 1 && r.entries.get(0).password.equals("New#Pass456abcR")
            && r.entries.get(0).url.equals("github.com") && r.entries.get(0).category.equals("Work") && r.entries.get(0).totp.equals(secret));
        check("roundtrip history", r.entries.get(0).history.size() == 1);
        check("roundtrip settings", r.idleMinutes == 9 && r.clipboardSeconds == 45 && r.genLength == 24);

        // Wrong password
        boolean wrong = false;
        try { PasswordManager.Vault.open(p, "wrong password!!".toCharArray()); } catch (AEADBadTagException ex) { wrong = true; }
        check("wrong password rejected (AEADBadTagException)", wrong);

        // Tamper detection
        byte[] raw = Files.readAllBytes(p); raw[raw.length - 5] ^= 0x01; Path tp = Paths.get("tamper.dat"); Files.write(tp, raw);
        boolean tampered = false;
        try { PasswordManager.Vault.open(tp, pw); } catch (AEADBadTagException ex) { tampered = true; }
        check("tampered file rejected", tampered);

        // Backup created on save(true)
        v.save(true);
        check("backup file created", Files.exists(Paths.get("t.dat.bak")));

        // verify + change master password
        check("verify correct", r.verify(pw));
        check("verify wrong", !r.verify("nope nope nope".toCharArray()));
        char[] npw = "brand new master pw!".toCharArray();
        v.changeMasterPassword(npw);
        check("old backup removed after password change", !Files.exists(Paths.get("t.dat.bak")));
        boolean oldFails = false;
        try { PasswordManager.Vault.open(p, pw); } catch (AEADBadTagException ex) { oldFails = true; }
        check("old password no longer opens vault", oldFails);
        PasswordManager.Vault r2 = PasswordManager.Vault.open(p, npw);
        check("new password opens vault with data intact", r2.entries.size() == 1 && r2.entries.get(0).history.size() == 1);

        // Legacy v1 file compatibility (replicates the first version's format)
        byte[] salt = new byte[16], iv = new byte[12]; new SecureRandom().nextBytes(salt); new SecureRandom().nextBytes(iv);
        SecretKeyFactory f = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        SecretKey key = new SecretKeySpec(f.generateSecret(new PBEKeySpec("legacy master pw".toCharArray(), salt, 210_000, 256)).getEncoded(), "AES");
        ByteArrayOutputStream pl = new ByteArrayOutputStream(); DataOutputStream d = new DataOutputStream(pl);
        d.writeInt(1); d.writeUTF("OldSite"); d.writeUTF("olduser"); d.writeUTF("oldpass"); d.writeUTF("oldnote");
        Cipher c = Cipher.getInstance("AES/GCM/NoPadding"); c.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(128, iv));
        ByteArrayOutputStream file = new ByteArrayOutputStream(); file.write(new byte[]{'P','M','V','1'}); file.write(salt); file.write(iv); file.write(c.doFinal(pl.toByteArray()));
        Path lp = Paths.get("legacy.dat"); Files.write(lp, file.toByteArray());
        PasswordManager.Vault lv = PasswordManager.Vault.open(lp, "legacy master pw".toCharArray());
        check("legacy v1 vault opens", lv.entries.size() == 1 && lv.entries.get(0).site.equals("OldSite") && lv.idleMinutes == 5);
        lv.save(true);
        PasswordManager.Vault lv2 = PasswordManager.Vault.open(lp, "legacy master pw".toCharArray());
        check("legacy vault upgrades to v3 on save", lv2.entries.size() == 1 && Files.readAllBytes(lp)[3] == '3');

        // CSV parse: quotes, commas, newlines, escaped quotes
        List<List<String>> rows = PasswordManager.parseCsv("a,b,c\r\n\"x,1\",\"he said \"\"hi\"\"\",\"line1\nline2\"\n,,\n");
        check("csv quoted comma", rows.get(1).get(0).equals("x,1"));
        check("csv escaped quote", rows.get(1).get(1).equals("he said \"hi\""));
        check("csv embedded newline", rows.get(1).get(2).equals("line1\nline2"));
        check("csv empty trailing fields", rows.size() == 3 && rows.get(2).size() == 3);

        // Chrome format
        List<PasswordManager.Entry> chrome = PasswordManager.parseCsvEntries("name,url,username,password,note\nGitHub,https://github.com/login,me,pw1,hello\n,https://example.org/x,u2,pw2,\nNoPw,https://a.b,u3,,\n");
        check("chrome import count (skips empty password)", chrome.size() == 2);
        check("chrome fields", chrome.get(0).site.equals("GitHub") && chrome.get(0).url.startsWith("https://github.com") && chrome.get(0).notes.equals("hello"));
        check("chrome site falls back to host", chrome.get(1).site.equals("example.org"));
        // Bitwarden format
        List<PasswordManager.Entry> bw = PasswordManager.parseCsvEntries("folder,favorite,type,name,notes,fields,reprompt,login_uri,login_username,login_password,login_totp\nWork,0,login,Slack,n,,0,https://slack.com,bob,secret!,jbsw y3dp ehpk 3pxp\n");
        check("bitwarden mapping", bw.size() == 1 && bw.get(0).category.equals("Work") && bw.get(0).username.equals("bob") && bw.get(0).totp.equals("JBSWY3DPEHPK3PXP"));
        boolean noCol = false; try { PasswordManager.parseCsvEntries("a,b\n1,2\n"); } catch (IOException ex) { noCol = true; }
        check("import rejects file without password column", noCol);
        check("passwords.txt import", PasswordManager.parseColonList("alice:pw:with:colons\nbad line\nbob:x\n").size() == 2
            && PasswordManager.parseColonList("alice:pw:with:colons").get(0).password.equals("pw:with:colons"));

        // CSV export -> import roundtrip with nasty characters
        List<PasswordManager.Entry> src = new ArrayList<>();
        src.add(new PasswordManager.Entry("Site, \"Inc\"", "us\"er", "p,w\nd", "multi\nline", "https://x.y", "Cat", "JBSWY3DPEHPK3PXP"));
        List<PasswordManager.Entry> back = PasswordManager.parseCsvEntries(PasswordManager.toCsv(src));
        check("export/import roundtrip", back.size() == 1 && back.get(0).site.equals("Site, \"Inc\"") && back.get(0).password.equals("p,w\nd")
            && back.get(0).notes.equals("multi\nline") && back.get(0).totp.equals("JBSWY3DPEHPK3PXP"));

        // Audit
        long now = System.currentTimeMillis();
        List<PasswordManager.Entry> es = new ArrayList<>();
        es.add(new PasswordManager.Entry("Weak", "u", "abc123", ""));
        es.add(new PasswordManager.Entry("Dup1", "u", "Str0ng!Passw0rd#Zq", ""));
        es.add(new PasswordManager.Entry("Dup2", "u", "Str0ng!Passw0rd#Zq", ""));
        PasswordManager.Entry old = new PasswordManager.Entry("Old", "u", "Un1que!Passw0rd#Xy", ""); old.updated = now - 400L * 86_400_000L; es.add(old);
        es.add(new PasswordManager.Entry("Good", "u", "G00d!Passw0rd#Mk9", ""));
        PasswordManager.AuditResult ar = PasswordManager.audit(es, now);
        check("audit counts (1 healthy of 5)", ar.total == 5 && ar.healthy == 1 && ar.percent() == 20);
        check("audit flags weak/reused/old", ar.lines.stream().anyMatch(s -> s.contains("Weak") && s.contains("weak"))
            && ar.lines.stream().anyMatch(s -> s.contains("Dup1") && s.contains("reused"))
            && ar.lines.stream().anyMatch(s -> s.contains("Old") && s.contains("not changed")));
        check("audit of empty vault = 100%", PasswordManager.audit(new ArrayList<>(), now).percent() == 100);

        // Generator
        boolean genOk = true;
        for (int i = 0; i < 200; i++) { String g = PasswordManager.generatePassword(20); genOk &= g.length() == 20 && PasswordManager.strengthScore(g) >= 4; }
        check("generator: 20 chars, strong", genOk);
        check("generator honours length 8..64", PasswordManager.generatePassword(8).length() == 8 && PasswordManager.generatePassword(64).length() == 64);


        // ---- v2 file compatibility (format written by the previous release)
        {
            byte[] salt2 = new byte[16], iv2 = new byte[12]; new SecureRandom().nextBytes(salt2); new SecureRandom().nextBytes(iv2);
            SecretKey k2 = new SecretKeySpec(SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256").generateSecret(new PBEKeySpec("v2 master pw!!".toCharArray(), salt2, 210_000, 256)).getEncoded(), "AES");
            ByteArrayOutputStream pl2 = new ByteArrayOutputStream(); DataOutputStream d2 = new DataOutputStream(pl2);
            d2.writeInt(1); d2.writeUTF("V2Site"); d2.writeUTF("u"); d2.writeUTF("pw"); d2.writeUTF("n"); d2.writeUTF("v2.example"); d2.writeUTF("Cat"); d2.writeUTF("");
            d2.writeLong(123456789L); d2.writeInt(1); d2.writeUTF("older"); d2.writeLong(111L);
            d2.writeInt(7); d2.writeInt(40); d2.writeInt(18);
            Cipher c2 = Cipher.getInstance("AES/GCM/NoPadding"); c2.init(Cipher.ENCRYPT_MODE, k2, new GCMParameterSpec(128, iv2));
            ByteArrayOutputStream f2 = new ByteArrayOutputStream(); f2.write(new byte[]{'P','M','V','2'}); f2.write(salt2); f2.write(iv2); f2.write(c2.doFinal(pl2.toByteArray()));
            Path p2 = Paths.get("v2.dat"); Files.write(p2, f2.toByteArray());
            PasswordManager.Vault v2 = PasswordManager.Vault.open(p2, "v2 master pw!!".toCharArray());
            PasswordManager.Entry e2 = v2.entries.get(0);
            check("v2 vault opens with fields/history/settings", e2.site.equals("V2Site") && e2.url.equals("v2.example") && e2.history.size() == 1
                && e2.updated == 123456789L && v2.idleMinutes == 7 && v2.clipboardSeconds == 40 && v2.genLength == 18 && v2.autoTypeDelay == 3);
            check("legacy ids are deterministic across devices", e2.id.equals(PasswordManager.legacyId("V2Site", "u", "pw"))
                && PasswordManager.Vault.open(p2, "v2 master pw!!".toCharArray()).entries.get(0).id.equals(e2.id));
        }

        // ---- two-device sync scenarios
        {
            Path sp = Paths.get("sync.dat"); Files.deleteIfExists(sp); Files.deleteIfExists(Paths.get("sync.dat.bak"));
            char[] spw = "shared master pw".toCharArray();
            PasswordManager.Vault base = PasswordManager.Vault.create(sp, spw);
            base.entries.add(new PasswordManager.Entry("Alpha", "u", "alphaPW", ""));
            base.entries.add(new PasswordManager.Entry("Beta", "u", "betaPW", ""));
            base.entries.add(new PasswordManager.Entry("Gamma", "u", "gammaPW", ""));
            check("initial save is SAVED", base.save(true) == PasswordManager.SaveStatus.SAVED);
            PasswordManager.Vault A = PasswordManager.Vault.open(sp, spw);
            PasswordManager.Vault B = PasswordManager.Vault.open(sp, spw);
            check("unchanged file reports UNCHANGED", A.syncFromDisk() == PasswordManager.SyncStatus.UNCHANGED);

            // B adds a new entry and edits Alpha; saves first
            B.entries.add(new PasswordManager.Entry("FromB", "ub", "bPW", ""));
            B.entries.stream().filter(x -> x.site.equals("Alpha")).findFirst().get().applyEdit(new PasswordManager.Entry("Alpha", "u", "alphaPW-v2", ""));
            check("B save SAVED", B.save(true) == PasswordManager.SaveStatus.SAVED);

            // A (stale) edits Beta, adds an entry, deletes Gamma, then saves -> must merge, not overwrite
            A.entries.stream().filter(x -> x.site.equals("Beta")).findFirst().get().applyEdit(new PasswordManager.Entry("Beta", "u", "betaPW-v2", ""));
            A.entries.add(new PasswordManager.Entry("FromA", "ua", "aPW", ""));
            PasswordManager.Entry gam = A.entries.stream().filter(x -> x.site.equals("Gamma")).findFirst().get();
            A.entries.remove(gam); A.recordDeletion(gam);
            check("stale A save => MERGED", A.save(true) == PasswordManager.SaveStatus.MERGED);
            java.util.Map<String, String> m = new java.util.HashMap<>();
            for (PasswordManager.Entry x : A.entries) m.put(x.site, x.password);
            check("merge keeps both devices' new entries", m.containsKey("FromA") && m.containsKey("FromB"));
            check("merge keeps B's edit of Alpha", "alphaPW-v2".equals(m.get("Alpha")));
            check("merge keeps A's edit of Beta", "betaPW-v2".equals(m.get("Beta")));
            check("merge applies A's deletion of Gamma", !m.containsKey("Gamma"));
            check("merge produced exactly 4 entries", A.entries.size() == 4);

            // B picks the merged result up via syncFromDisk (no save needed)
            check("B syncFromDisk => MERGED", B.syncFromDisk() == PasswordManager.SyncStatus.MERGED);
            java.util.Map<String, String> mb = new java.util.HashMap<>();
            for (PasswordManager.Entry x : B.entries) mb.put(x.site, x.password);
            check("B now matches A (4 entries, deletion applied)", mb.equals(m));
            check("B is now in sync (UNCHANGED)", B.syncFromDisk() == PasswordManager.SyncStatus.UNCHANGED);
            check("B can save plainly afterwards", B.save(true) == PasswordManager.SaveStatus.SAVED);

            // Same entry edited on both devices: newest edit wins
            PasswordManager.Vault C = PasswordManager.Vault.open(sp, spw);
            PasswordManager.Vault D = PasswordManager.Vault.open(sp, spw);
            PasswordManager.Entry cE = C.entries.stream().filter(x -> x.site.equals("Beta")).findFirst().get();
            PasswordManager.Entry dE = D.entries.stream().filter(x -> x.site.equals("Beta")).findFirst().get();
            cE.applyEdit(new PasswordManager.Entry("Beta", "u", "beta-from-C", "")); cE.modified = 1_000_000L;
            dE.applyEdit(new PasswordManager.Entry("Beta", "u", "beta-from-D", "")); dE.modified = 2_000_000L;
            C.save(true);
            D.save(true);
            PasswordManager.Vault fin = PasswordManager.Vault.open(sp, spw);
            check("conflicting edits: newest modified wins", fin.entries.stream().anyMatch(x -> x.site.equals("Beta") && x.password.equals("beta-from-D")));

            // Deletion vs later edit: edit after deletion wins (entry survives)
            PasswordManager.Vault E1 = PasswordManager.Vault.open(sp, spw);
            PasswordManager.Vault E2 = PasswordManager.Vault.open(sp, spw);
            PasswordManager.Entry victim = E1.entries.stream().filter(x -> x.site.equals("Alpha")).findFirst().get();
            E1.entries.remove(victim); E1.tombstones.put(victim.id, 5_000L); E1.save(true);
            PasswordManager.Entry edited = E2.entries.stream().filter(x -> x.site.equals("Alpha")).findFirst().get();
            edited.applyEdit(new PasswordManager.Entry("Alpha", "u", "alpha-edited-later", "")); // modified = now > 5000
            E2.save(true);
            check("edit newer than a deletion keeps the entry", PasswordManager.Vault.open(sp, spw).entries.stream().anyMatch(x -> x.site.equals("Alpha") && x.password.equals("alpha-edited-later")));

            // Deletion newer than edit removes the entry everywhere
            PasswordManager.Vault F1 = PasswordManager.Vault.open(sp, spw);
            PasswordManager.Vault F2 = PasswordManager.Vault.open(sp, spw);
            PasswordManager.Entry f2e = F2.entries.stream().filter(x -> x.site.equals("FromB")).findFirst().get();
            f2e.modified = 10L; f2e.applyEdit(new PasswordManager.Entry("FromB", "ub", "bPW-x", "")); f2e.modified = 10L;
            F2.save(true);
            PasswordManager.Entry f1e = F1.entries.stream().filter(x -> x.site.equals("FromB")).findFirst().get();
            F1.entries.remove(f1e); F1.recordDeletion(f1e); F1.save(true);
            check("deletion newer than edit removes entry", PasswordManager.Vault.open(sp, spw).entries.stream().noneMatch(x -> x.site.equals("FromB")));

            // Undo of a delete clears the tombstone so the entry stays
            PasswordManager.Vault G = PasswordManager.Vault.open(sp, spw);
            PasswordManager.Entry gone = G.entries.get(0);
            G.entries.remove(gone); G.recordDeletion(gone); G.save(true);
            G.entries.add(gone); G.restore(gone); G.save(true);
            check("undo delete survives saves/merges", PasswordManager.Vault.open(sp, spw).entries.stream().anyMatch(x -> x.id.equals(gone.id)) && !G.tombstones.containsKey(gone.id));

            // Master password changed on another device => stale device must not overwrite it
            PasswordManager.Vault H1 = PasswordManager.Vault.open(sp, spw);
            PasswordManager.Vault H2 = PasswordManager.Vault.open(sp, spw);
            H1.changeMasterPassword("a totally new master".toCharArray());
            H2.entries.add(new PasswordManager.Entry("StaleAdd", "u", "p", ""));
            check("stale device sees NEEDS_RELOCK", H2.syncFromDisk() == PasswordManager.SyncStatus.NEEDS_RELOCK);
            check("stale save => CONFLICT_COPY (never overwrites)", H2.save(true) == PasswordManager.SaveStatus.CONFLICT_COPY && H2.conflictCopy != null && Files.exists(H2.conflictCopy));
            boolean stillNew = false;
            try { PasswordManager.Vault.open(sp, "a totally new master".toCharArray()); stillNew = true; } catch (Exception ex) { }
            check("newer vault untouched and opens with new password", stillNew);
            PasswordManager.Vault recovered = PasswordManager.Vault.open(H2.conflictCopy, spw);
            check("conflict copy opens with old password and has the stale change", recovered.entries.stream().anyMatch(x -> x.site.equals("StaleAdd")));

            // partially-synced (garbage) file => RETRY, not a crash
            PasswordManager.Vault J = PasswordManager.Vault.open(Paths.get("legacy.dat"), "legacy master pw".toCharArray());
            Path jp = Paths.get("legacy.dat"); byte[] jb = Files.readAllBytes(jp);
            Files.write(jp, Arrays.copyOf(jb, jb.length - 30));
            check("truncated file => RETRY", J.syncFromDisk() == PasswordManager.SyncStatus.RETRY);
        }

        // ---- moving the vault to another folder
        {
            Path mvSrc = Paths.get("mv-src.dat"); Files.deleteIfExists(mvSrc);
            char[] mpw = "move master pw!".toCharArray();
            PasswordManager.Vault mv = PasswordManager.Vault.create(mvSrc, mpw);
            mv.entries.add(new PasswordManager.Entry("MoveMe", "u", "p", "")); mv.save(true);
            Path dst = Paths.get("moved-dir", "sub", "vault.dat"); Files.deleteIfExists(dst);
            Path mvOld = mv.moveTo(dst);
            check("moveTo returns old path and copies file", mvOld.equals(mvSrc) && Files.exists(dst) && Files.exists(mvSrc));
            mv.entries.add(new PasswordManager.Entry("AfterMove", "u", "p2", "")); 
            check("save after move writes to new location", mv.save(true) == PasswordManager.SaveStatus.SAVED);
            PasswordManager.Vault reopened = PasswordManager.Vault.open(dst, mpw);
            check("moved vault has all entries", reopened.entries.size() == 2);
            PasswordManager.Vault.deleteVaultFiles(mvOld);
            check("old copy removed", !Files.exists(mvSrc));
            boolean refused = false;
            try { mv.moveTo(dst); } catch (IOException ex) { refused = true; }
            check("moveTo refuses to overwrite an existing vault", refused);
        }

        // ---- auto-type sequences
        {
            PasswordManager.Entry at = new PasswordManager.Entry("S", "alice", "pa$$w0rd!", "", "", "", secret);
            check("login sequence = user, TAB, password", PasswordManager.autoTypeSequence(at, "login", false, 0).equals(Arrays.asList("alice", "\t", "pa$$w0rd!")));
            check("login + Enter", PasswordManager.autoTypeSequence(at, "login", true, 0).equals(Arrays.asList("alice", "\t", "pa$$w0rd!", "\n")));
            PasswordManager.Entry nu = new PasswordManager.Entry("S", "", "pw", "");
            check("login without username skips TAB", PasswordManager.autoTypeSequence(nu, "login", false, 0).equals(Arrays.asList("pw")));
            check("password-only sequence", PasswordManager.autoTypeSequence(at, "password", false, 0).equals(Arrays.asList("pa$$w0rd!")));
            check("totp sequence = current code", PasswordManager.autoTypeSequence(at, "totp", false, 59_000L).equals(Arrays.asList("287082")));
            boolean unk = false; try { PasswordManager.autoTypeSequence(at, "bogus", false, 0); } catch (IllegalArgumentException ex) { unk = true; }
            check("unknown mode rejected", unk);
        }


        // ---- default vault locations and icon containers
        check("default path: Windows (APPDATA)", PasswordManager.defaultVaultPath("Windows 11", "C:\\Users\\k\\AppData\\Roaming", null, "C:\\Users\\k").toString().endsWith("PasswordManager" + java.io.File.separator + "vault.dat"));
        check("default path: macOS", PasswordManager.defaultVaultPath("Mac OS X", null, null, "/Users/k").toString().contains("Library/Application Support/PasswordManager"));
        check("default path: Linux XDG", PasswordManager.defaultVaultPath("Linux", null, "/data/xdg", "/home/k").toString().startsWith("/data/xdg/password-manager"));
        check("default path: Linux fallback", PasswordManager.defaultVaultPath("Linux", null, null, "/home/k").toString().startsWith("/home/k/.local/share/password-manager"));
        byte[] png = PasswordManager.png(PasswordManager.logoImage(64));
        check("icon png has PNG signature", png.length > 100 && (png[0] & 0xFF) == 0x89 && png[1] == 'P');
        byte[] ico = PasswordManager.ico(png);
        check("ico header is valid", ico[2] == 1 && ico[4] == 1 && ico.length == 22 + png.length);
        byte[] icns = PasswordManager.icns(png, png);
        check("icns header is valid", icns[0] == 'i' && icns[3] == 's' && icns.length == 8 + 2 * (8 + png.length));

        System.out.println(fails == 0 ? "ALL PASSED" : (fails + " FAILED"));
        System.exit(fails == 0 ? 0 : 1);
    }
}
