package com.squareup.subzero;

import com.beust.jcommander.JCommander;
import com.beust.jcommander.Parameter;
import com.google.protobuf.TextFormat;
import com.ncipher.km.nfkm.AdminKeys;
import com.ncipher.km.nfkm.CardSet;
import com.ncipher.km.nfkm.Key;
import com.ncipher.km.nfkm.Module;
import com.ncipher.km.nfkm.SecurityWorld;
import com.ncipher.km.nfkm.Slot;
import com.ncipher.nfast.NFException;
import com.ncipher.nfast.NFUtils;
import com.ncipher.nfast.connect.NFConnection;
import com.ncipher.nfast.connect.StatusNotOK;
import com.ncipher.nfast.marshall.M_ACL;
import com.ncipher.nfast.marshall.M_Act_Details_NVMemOpPerms;
import com.ncipher.nfast.marshall.M_Action;
import com.ncipher.nfast.marshall.M_ByteBlock;
import com.ncipher.nfast.marshall.M_CertType;
import com.ncipher.nfast.marshall.M_CertType_CertBody_SigningKey;
import com.ncipher.nfast.marshall.M_Certificate;
import com.ncipher.nfast.marshall.M_CertificateList;
import com.ncipher.nfast.marshall.M_Cmd;
import com.ncipher.nfast.marshall.M_Cmd_Args_GetKeyInfo;
import com.ncipher.nfast.marshall.M_Cmd_Args_GetKeyInfoEx;
import com.ncipher.nfast.marshall.M_Cmd_Args_NVMemAlloc;
import com.ncipher.nfast.marshall.M_Cmd_Args_NVMemOp;
import com.ncipher.nfast.marshall.M_Cmd_Reply_GetKeyInfo;
import com.ncipher.nfast.marshall.M_Cmd_Reply_GetKeyInfoEx;
import com.ncipher.nfast.marshall.M_Command;
import com.ncipher.nfast.marshall.M_FileID;
import com.ncipher.nfast.marshall.M_FileInfo;
import com.ncipher.nfast.marshall.M_Hash;
import com.ncipher.nfast.marshall.M_KeyHash;
import com.ncipher.nfast.marshall.M_KeyID;
import com.ncipher.nfast.marshall.M_ModuleID;
import com.ncipher.nfast.marshall.M_NVMemOpType;
import com.ncipher.nfast.marshall.M_NVMemOpType_OpVal_Write;
import com.ncipher.nfast.marshall.M_PermissionGroup;
import com.ncipher.nfast.marshall.M_Reply;
import com.ncipher.nfast.marshall.M_SlotType;
import com.ncipher.nfast.marshall.M_Status;
import com.ncipher.nfast.marshall.M_UseLimit;
import com.ncipher.provider.km.nCipherKM;
import com.squareup.protos.subzero.service.Service.CommandRequest;
import com.squareup.protos.subzero.service.Service.CommandResponse;
import com.squareup.subzero.framebuffer.Framebuffer;
import com.squareup.subzero.framebuffer.Screens;
import com.squareup.subzero.ncipher.NCipher;
import com.squareup.subzero.ncipher.NCipherLoadSoftcard;
import com.squareup.subzero.shared.SubzeroUtils;
import java.security.Security;
import java.util.Arrays;
import org.spongycastle.util.encoders.Hex;

import static com.google.common.base.Charsets.UTF_8;
import static com.google.common.io.BaseEncoding.base64;
import static com.ncipher.nfast.marshall.M_Act.NVMemOpPerms;
import static java.lang.String.format;

public class SubzeroGui {
  @Parameter(names = "--help", help = true)
  private boolean help = false;

  @Parameter(names = "--debug") public String debug = null;

  // UI test runs through all the screens without needing an HSM or Subzero server
  @Parameter(names = "--uitest") public Boolean uiTest = false;

  @Parameter(names = "--ncipher") public Boolean nCipher = false;

  // If missing or incorrect, will prompt for a password on stdin.
  @Parameter(names = "--ocs-password") public String ocsPassword;

  // By default, subzero listens on this port, which is allocated in Registry
  @Parameter(names = "--port") public int port = 32366;

  // Almost always you want to talk to subzero on localhost
  @Parameter(names = "--hostname") public String hostname = "localhost";

  // Needed for bootstrapping
  @Parameter(names = "--create-pub-key-encryption-key") public Boolean createPubKeyEncryptionKey = false;

  public SubzeroConfig config;
  private Screens screens;

  /**
   * We pass the cli object into functions which can use it to draw screens.
   * If null, you're running in debug mode and screens should probably use text instead.
   *
   * @return a screens object to interact with the user
   */
  public Screens getScreens() {
    return screens;
  }

  public static void main(String[] args) throws Exception {
    SubzeroGui subzero = new SubzeroGui();

    JCommander jCommander = JCommander.newBuilder()
        .addObject(subzero)
        .build();
    jCommander.setProgramName("Subzero");
    jCommander.parse(args);
    if (subzero.help) {
      jCommander.usage();
      return;
    }

    System.out.println("This program draws to a framebuffer. If you are only seeing this output,");
    System.out.println("then something has gone wrong. Please report this error.");

    subzero.config = SubzeroConfig.load(subzero.nCipher);

    subzero.blah();

    if (subzero.uiTest) {
      subzero.uiTest();
    } else if (subzero.debug != null) {
      subzero.debugMode();
    } else {
      subzero.interactive();
    }
  }

  private M_KeyHash loadDataSigner(SecurityWorld sw) throws Exception {
    Module m = getUsableModule(sw);
    Slot s = getSlot(m, M_SlotType.SmartCard);

    CardSet[] cardSets = sw.getCardSets(null);
    if (cardSets.length > 1) {
      throw new IllegalStateException("more than one OCS detected");
    }
    if (cardSets.length == 0) {
      throw new IllegalStateException("no existing OCS found");
    }
    Slot slot = m.getSlot(0);

    System.out.println("OCS found");
    CardSet ocsCardSet = cardSets[0];

    // TODO: should ocsCardSet.load get called after renderLoading?
    ocsCardSet.load(slot, new NCipherLoadSoftcard("prout"));

    Key key = sw.getKey("seeinteg", "datasigner");
    M_KeyID keyId = key.load(s);

    M_Cmd_Args_GetKeyInfoEx args = new M_Cmd_Args_GetKeyInfoEx(0, keyId);
    M_Reply xact = xact(sw.getConnection(), new M_Command(M_Cmd.GetKeyInfoEx, 0, args));
    return ((M_Cmd_Reply_GetKeyInfoEx)xact.reply).hash;
  }

  /**
   * Attempt to:
   * 1. allocate a NVRAM.
   * 2. write magic-version to it.
   * 3. change the ACL to require the data signer key.
   */
  private void blah() throws Exception {    nCipherKM provider = new nCipherKM();
    Security.addProvider(provider);
    SecurityWorld sw = nCipherKM.getSW();

    M_CertificateList acsCert = null;
    acsCert = buildAcsCert(sw);

    // Load the datasigner key
    M_KeyHash dataKey = new M_KeyHash();
    dataKey.value = Hex.decode("38ae947b6b4ae0e97b7dae1caf77b9fa19d4019d"); //loadDataSigner(sw);"

    // Allocate NVRAM. Permissions are:
    // - anyone can read
    // - datasigner can write
    // - ACS can write
    M_FileInfo fileInfo = new M_FileInfo(0, 100, new M_FileID("subzero....".getBytes(UTF_8)));
    M_PermissionGroup permissionGroups[] = new M_PermissionGroup[] {
      new M_PermissionGroup(0, new M_UseLimit[] {}, new M_Action[] {
          new M_Action(NVMemOpPerms, new M_Act_Details_NVMemOpPerms(
              M_Act_Details_NVMemOpPerms.perms_Write))
      }),
      new M_PermissionGroup(0, new M_UseLimit[] {}, new M_Action[] {
          new M_Action(NVMemOpPerms, new M_Act_Details_NVMemOpPerms(
              M_Act_Details_NVMemOpPerms.perms_Write))
      }),
      new M_PermissionGroup(0, new M_UseLimit[] {}, new M_Action[] {
          new M_Action(NVMemOpPerms, new M_Act_Details_NVMemOpPerms(
              M_Act_Details_NVMemOpPerms.perms_Read | M_Act_Details_NVMemOpPerms.perms_GetACL))
      }),
    };
    permissionGroups[0].set_certifier(dataKey);
    permissionGroups[1].set_certifier(acsCert.certs[0].keyhash);

    M_ACL acl = new M_ACL(permissionGroups);
    M_Cmd_Args_NVMemAlloc args = new M_Cmd_Args_NVMemAlloc(new M_ModuleID(1), 0, fileInfo, acl);
    M_Command m_command = new M_Command(M_Cmd.NVMemAlloc, 0, args);
    m_command.set_certs(acsCert);
    M_Reply rep = sw.getConnection().transact(m_command);
    if (rep.status != M_Status.OK) {
      throw new StatusNotOK("NVMemAlloc returned status " + NFUtils.errorString(rep.status, rep.errorinfo));
    }

    // Write initial value
    byte[] data = new byte[100];
    data[0] = 0x20;
    M_Cmd_Args_NVMemOp args2 = new M_Cmd_Args_NVMemOp(new M_ModuleID(1), 0, new M_FileID("subzero....".getBytes(UTF_8)),
        M_NVMemOpType.Write, new M_NVMemOpType_OpVal_Write(new M_ByteBlock(data)));
    M_Command cmd2 = new M_Command(M_Cmd.NVMemOp, 0, args2);
    cmd2.set_certs(acsCert);
    M_Reply m_reply = xact(sw.getConnection(), cmd2);


    return;
  }

  private static Module getUsableModule(SecurityWorld world) throws Exception {
    Module modules[] = world.getModules();
    for (Module module : modules) {
      if (module.isUsable()) {
        return module;
      }
    }
    throw new Exception("no usable module?");
  }

  private static Slot getSlot(Module module, int slotType) {
    Slot[] smartCardSlots = Arrays.stream(module.getSlots())
        .filter(s -> s.getData().phystype == slotType)
        .toArray(Slot[]::new);
    if (smartCardSlots.length == 0) {
      throw new IllegalStateException(format("no slots of type '%s' found", M_SlotType.toString(slotType)));
    } else if (smartCardSlots.length > 1) {
      throw new IllegalStateException(format("too many slots of type '%s' found", M_SlotType.toString(slotType)));
    }
    return smartCardSlots[0];
  }

  private static M_Reply xact(NFConnection conn, M_Command cmd) throws NFException {
    M_Reply rep = conn.transact(cmd);
    if (rep.status != M_Status.OK) {
      throw new StatusNotOK("Status "
          + M_Status.toString(rep.status)
          + " from "
          + M_Cmd.toString(cmd.cmd)
          + " command");
    }
    return rep;
  }

  private static M_KeyHash doGetKeyHash(NFConnection conn, M_KeyID keyId) throws NFException {
    M_Reply reply = xact(conn, new M_Command(M_Cmd.GetKeyInfo, 0, new M_Cmd_Args_GetKeyInfo(keyId)));
    M_Cmd_Reply_GetKeyInfo getKeyInfoReply = (M_Cmd_Reply_GetKeyInfo) reply.reply;
    return getKeyInfoReply.hash;
  }

  private static M_CertificateList buildAcsCert(SecurityWorld sw) throws Exception {
    Module m = getUsableModule(sw);
    Slot s = getSlot(m, M_SlotType.SmartCard);

    AdminKeys akeys = sw.loadAdminKeys(s, new int[] {SecurityWorld.NFKM_KNSO}, new NCipherLoadSoftcard("prout"));
    M_KeyID cardSetKeyId = akeys.KeyIds[0];

    // certifierKeyHash (key hash from the ACL), cardSetKeyHash (key hash we just got from the cards),
    // and hknsoKeyHash (world Security Officer's key hash) should all be the same
    M_KeyHash cardSetKeyHash = doGetKeyHash(sw.getConnection(), cardSetKeyId);
    M_Hash hknsoKeyHash = sw.getData().hknso;

    if (!Arrays.equals(cardSetKeyHash.value, hknsoKeyHash.value)) {
      throw new IllegalStateException("Admin cardset key hash does not match source world Security Officer's key hash.");
    }

    return new M_CertificateList(new M_Certificate[] {
        new M_Certificate(cardSetKeyHash, M_CertType.SigningKey,
            new M_CertType_CertBody_SigningKey(cardSetKeyId))});
  }

  private void debugMode() throws Exception {
    byte[] rawCmd = base64().decode(debug);
    CommandRequest commandRequest = CommandRequest.parseFrom(rawCmd);

    InternalCommandConnector conn = new
        InternalCommandConnector(hostname, port);
    CommandResponse commandResponse = CommandHandler.dispatch(this, conn, commandRequest);
    String response = base64().encode(commandResponse.toByteArray());

    // Pretty print the response
    String debugString = TextFormat.shortDebugString(commandResponse);
    System.out.println(debugString);

    // The response is what the server will receive via QR-Code.
    SubzeroUtils.printQrCode(response);
    System.out.println(response);
  }

  private void interactive() throws Exception {
    screens = new Screens(new Framebuffer(config), config.getTeamName());

    try {
      if (nCipher) {
        new NCipher().healthCheck();
      }

      while (true) {
        String input = screens.readQRCode();

        byte[] proto = base64().decode(input);

        CommandRequest commandRequest = CommandRequest.parseFrom(proto);

        CommandResponse response =
            CommandHandler.dispatch(this, new InternalCommandConnector(hostname, port), commandRequest);
        System.out.println(response.toString());

        String encoded = base64().encode(response.toByteArray());

        Screens.ExitOrRestart command = screens.displayQRCode(encoded);
        if (command == Screens.ExitOrRestart.Exit) {
          return;
        }
      }
    } catch (Exception e) {
      screens.exception(e);
    }
  }

  /**
   * This goes through the various screens, so you can test changes to them without needing to
   * worry about any system state, run Subzero, etc.
   */
  private void uiTest() throws Exception {
    screens = new Screens(new Framebuffer(config), config.getTeamName());

    try {
      while (true) {
        String input = screens.readQRCode();

        if (!screens.approveAction(
            "You are trying to transfer 10000 btc to hackers. Sounds cool?")) {
          System.out.println("Rejected!");
          return;
        }

        screens.promptForOperatorCard("Please insert Operator Card and then press enter");

        String passwordPrompt = "Please type your Operator Card password";
        while (true) {
          String password = screens.promptPassword(passwordPrompt);
          if (password.equals("ponies")) {
            break;
          }
          passwordPrompt = "Incorrect. Please type your Operator Card password";
        }

        screens.removeOperatorCard("Please remove Operator card and then hit <enter>.");

        // Please wait screen should now be displayed
        Thread.sleep(3000);

        // Generate a big QR code:
        String big = new String(new char[1999]).replace("\0", "M");
        screens.displayQRCode(big); // return value ignored so exit doesn't work
        // reflect back the original scanned QR code:
        Screens.ExitOrRestart command = screens.displayQRCode(input);
        if (command == Screens.ExitOrRestart.Exit) {
          return;
        }
        // otherwise command was restart, and we loop.
      }
    } catch (Exception e) {
      screens.exception(e);
    }
  }
}
