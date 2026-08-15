/* ══ FILE: no_so_crypto.c ══
 *
 * Fully self-contained C implementation of the INE QR pipeline — no .so
 * loading, no Unicorn emulation. C equivalent of `ine-qr-py/no_so_pipeline.py`.
 *
 * All AES ciphertexts and key/IV pairs are hardcoded constants recovered from
 * libPersonalCode.so .rodata (verified bit-exact across every implementation).
 *
 * Pipeline:
 *   Round 1   — AES(key1/iv1) → RSA-XML#1, AES(key1/iv1) → b64,
 *               RSA-decrypt(b64, key#1) → RSA-XML#2.
 *   Round 2   — AES(key2/iv2) → RSA-XML#3, AES(key2/iv2) → b64,
 *               RSA-decrypt(b64, key#3) → RSA-XML#4.
 *   Stage A   — RSA-decrypt(buf2, key#2) → 970-byte intermediate (PKCS#1 type 02).
 *   Stage B   — RSA-verify((buf1 + decrypted_buf2)[:1024], key#4)
 *               → 1013-byte inner blob (PKCS#1 type 01 signature padding).
 *   Stage C   — Reassemble work buffer, 6-bit unpack the encoded text, and
 *               reconstruct the WebP image from a hardcoded header table
 *               interleaved with payload bytes from the work buffer.
 *
 * The output buffer has the same layout produced by the emulated pc():
 *   [text_len:u16 BE][encoded text][img_len:u16 BE][WebP image]
 *
 * so that the existing `decode_and_write()` from output_decode.c can consume
 * it unchanged.
 */

#include "../include/wasm_pipeline.h"
#include "../vendor/bignum.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ──────────────────────────────────────────────────────────────────── */
/* Hardcoded constants (extracted from libPersonalCode.so .rodata).      */
/* ──────────────────────────────────────────────────────────────────── */

/* AES key/IV #1 — used for Round 1 (CT_R1_KEY, CT_R1_BLOB).
 * Verified output of NEON SIMD blocks 0/1 over .rodata only. */
static const char NS_AES_KEY1_HEX[] =
    "0001029836537892876377726A4E78E77F987CC321180281AABB019654321000";
static const char NS_AES_IV1_HEX[]  =
    "0192C58D36E47A589AF01928376428AA";

/* AES key/IV #2 — used for Round 2 (CT_R2_KEY, CT_R2_BLOB).
 * Verified output of NEON SIMD blocks 2/3 over .rodata only. */
static const char NS_AES_KEY2_HEX[] =
    "00010298310293A573C93A745AD38298F36E0928777726A4E78E77F1AABB0197";
static const char NS_AES_IV2_HEX[]  =
    "10293A573C93A745AD38298F36E09287";

/* WebP header lookup table (from .so .rodata @ 0x124b10, 23 entries used).
 * Filled into specific positions of the reconstructed WebP container; the
 * remaining header bytes (positions 4,5,16,17,20,21,28) come from the
 * working-buffer payload. */
static const uint8_t NS_WEBP_HDR[23] = {
    0x52, 0x49, 0x46, 0x46, 0x00, 0x00, 0x57, 0x45, 0x42, 0x50,
    0x56, 0x50, 0x38, 0x20, 0x00, 0x00, 0x00, 0x9D, 0x01, 0x2A,
    0x60, 0x00, 0x00
};

/* AES-CBC ciphertexts from .rodata.  These are null-terminated ASCII hex
 * strings in the .so; we embed them directly so the binary is fully
 * self-contained.  See ine-qr-py/no_so_pipeline.py for the canonical source. */
static const char CT_R1_KEY[] =
    "E6ABDA5F60C48C346C858F1163567575BA3C4BA09A992CC794A215E195CDC3112579A57B22DA"
    "A66DE79318BFEB788F9EAFD876BE8CFDD4E5FE241F8ACA1EAF8326A6348303D1E6E777DB763E"
    "33FF3421692F4C23B25F41C15BD338A25B9F271E8963508F92231E90CA9DB2249F613E8ADFAF"
    "7F39C42E41AE1A958840B1F8A84CB3281CFF820125C85DD92CC6C2FC17FF81A20185E90AC334"
    "4EBB97A3B6C25D6321CFA3F796FC279E02A253C700A8D9D19836F48CE8DBD766F513BEA3FE42"
    "04025B1733CB6FE94F0E391672750BBD4A38FA4793F1E3E32D9202113EC41CE376B16292D1DB"
    "1D075D12013408792D8E7C44F592F388FCDF264D9E00BDF3204FB587E671AFE94E413736D448"
    "0E854F68C64684BD50564E381ACFB00E8FE04D4FDE858FD1ABD164A777F879FA7286CEA8A024"
    "2E48AC53603E9F907CBD4003647BC6FD894A4D3E9D26305230BD1B32F42A720145F9906810F9"
    "0046E0533095BA5523BA5D48C6F958300F78E0F79DE97A1B9106FFC05F00425E4749B59DD468"
    "3544C367A54AE36879E2EB82F40FB19A835C2844A79485708B35D90773444668FB9FFC773568"
    "4F27C461F3FCF795923C3D33FBC185D0A71B852C18CBBD609D21D3370CBEA024BCBFFF2741BE"
    "11FC18B75198C1715500C9D04537C264E84BD83253986C312B18A486014C595719710E80D88F"
    "35406985E0331A32D2A6D4A97B692B092D6902EE8246AB6F3CEECD7ABF78B5C4C140A043EDBA"
    "01A4C78D561749884AF77A0397036DE333A0AED4385D764BC2ADC5E6D4AEC1871733B5D56BEB"
    "EF57EE126B13081D65C777EF4739D7F61E04A32E8FAB93EE43A10844AD0B0A5B586A191AD274"
    "DF0C2366B35CF3B10EB1012B0E56E8023C0119D919304ADA0BE1B1DC6F836D00E386E030FB5C"
    "15155223AD69AB31726C50070D03DC412E74AA67B33A1DF21C399667339C03570DE948E8F1F9"
    "DFC12CA207AACD1A0B33AB417F0809BC4367E2D82B167C06DBB3233D70062C89753CCD4A260B"
    "5A25227D177118C275DB2B0D13689BF38894E1985781478C0AB62830EAEA1216B6A6826A2242"
    "AFE99D7E8C20FAC2FF65C43B36B61B3271EF94E0714F01D6C55558721ACC643A5BB50D77C465"
    "0B6D569F1891C8B9FE5D5DDD130288CF079A0C7C2680BFC8881FCD14AFDEC7B1E1ACCB3AFD5E"
    "FCB97E3DE41F9348D9250BD741B43A061018B99802AA101D414F59D7571C5AD331E8B64109D8"
    "F9CF9416529AACE74C60117F6540399D440E2AE931AC1AE838339AE3909B74FEF3408E9A41A7"
    "65CC20E127861109024771D2899480279FD6A1490760934AD4764DEA542C686666E66144771A"
    "A062628844502915DA7FD443DD93DF7D3C3DCB79B91C9445C22312CB4EF89C58352062F1FC66"
    "ED0BD57AC2EA7FFA7C013DBB3852B09D6B4AFD44C7CDC8FAE0C6DC27544E498CC380549F9793"
    "984DE989E5FB8F0D2F2630E77C7DF9AF83A696E9D9AA28B23314D30021995D72F354371BD71D"
    "D99C081DB2541919FA0720B915B886C61998BC553A1F3AEDA7DB122AF030F38077C284BC2EC0"
    "9DC91068D4F41DA855AE845F2B468CA26AAC43CB70B3F343DA1B9D0C60A94BC93C0DF0E807B4"
    "5EF796270721667F381A1C0508311DEC2F64A4A166425FB23743878AA27FAF59BCF4CF4AB8BC"
    "C8F8DC64E4D1273268C89790DBAFBE7FB6B126A49BEBA8D646AC77C5C7A72A120231728B43FD"
    "C4D5E801FB3FAFFF159E43C351452F1F3179020B26FE6B07CD15D3BF9890B1811DA135D9E4BB"
    "61DCCFF0BA7096348850F2BB80E754EFB09B5F592D5838001C8F7E4DC2E69F5567783DB32AB8"
    "691F0E1B3872C0C2CD19137278C9846D1635A11E5A343768F6DCC83BCD6EEF446941C88C4E1E"
    "BE3B0980FCF1839AA3B2AA1FABF59D16E897C6217079CD358CF5AD36F617D70A10BACED8AC96"
    "8BFB0777BB7FE7BF287B533AC06714EF790D82E43A371EE3428751A07CDF43D6A619AB5FB008"
    "5B6DEBB158E68BEAE981D4E7AF3C2D7E1E8AE9E84496036A3EA1B5C2F9AB10D8EFE40DE6D4F6"
    "965ABC24AC78413B0D4F52B6";

static const char CT_R1_BLOB[] =
    "1169B94A25A597817FF30D3FC4821AC5B6B36AE948E9C5D0CA12F15364CB8E845D7C1A1C7B55"
    "5D332399C6468CACA2EE4116FD114C5148F13DC1B90A40FEDD2D91BEE7C378067CEC2452B5B1"
    "F4D925ED01C29C6952D3D4A9C04773573C10F4A1DB8F172F60BCF19E110E3A39EA8F18C4ADA6"
    "68B0E7F40116AFAE49F04D0F2971D3306BA938C93C1C8F697D12F8D2801773E5DDFB272F0726"
    "B294106D8466DC0359B9068B56A821DC610D8E3B9739A0B22FD1C13EA1908C8BA5B03509D700"
    "418CD4D0B26C3BE3C9B9444D57B3A1F70A83351D3798BB39E7A0A8D17132A1D88147161EDBBE"
    "C16E51BF4F038AF9A465EB41FC6DD77F0DD109CC26FCF1584575BA8F790AF1BDFFFD7A8E8ADF"
    "7770F0F14B82003345F1BA8870BC936D387B787983C90B5709604FE89BED97956FDA46125598"
    "B44F5BB0CBFC927814A2D1D64FDF6A822ADDC31CFFEC47DF73E74F45DD1F281928C2DD22D7DE"
    "C93828E86E96EADDD8892A70FBA6BCF123E50B87583004DEBCFB772B0E932C5FA33B02288BD4"
    "7199A2105DEE5F3534534FF49EB00C3496BE3FDF1ED5239F77230DD6C4AB933BA0B0F82D924F"
    "D5423D824CCFA2C0A4A62A0E972DB0801D4ECC03ABDBA74B09F9C7F265C5762E91351D1311E8"
    "0761911C97EC9232F043D3C12BC096C448D851929D430998F906ED1166301C2A8249D0B67670"
    "F629D5385402DA6FD0A3E9AFDEB75CE3D03BBA62E52DC269D2DFD35AC140112E0ACDDD4E007A"
    "8A779438134E47786FFA095499E3CA5FECD3ACD2FB31CB76BE744228FDFD559C5813BEF41C97"
    "E0DBEC8ECD18025BCD40534062D605BFCD57E1DFD7C8E042889D1250696864C5653C2E9B52DF"
    "FFD51AFC96A4060BF4E331E076390F8F705E9231C4DC8D3F1A030A69BAA6A5435E3BC7B82250"
    "EDEE557C2A10690151C8AE391598EEF77FDBFA76A8403BD2A7716112258BCA1FFEB8BF53E3E2"
    "E69E800ABDA596A4C839CBB78B3ED33D52E26B32CDF8B3AB3E5A039EBD3B5D312631F8C88781"
    "C8573F4193CB009E5169BE454C4FE22184166FDD5E68362E0BA62B372D09C34F070B9CA7A527"
    "20B33CD523BF1818ED99B88347FE343C4561DDC5E7291D155BAE1E0768BCB45EEEA82F70800E"
    "7763E9D10B0B2D916604F1123B6CCF3C300E043EB5207B390D605670E742B0B6192559B09B32"
    "1A65631C8221C2C4E21426D3D7CEA5412EC7444283599BA338B68ABE660FC215C36C1DBF73A3"
    "D3242AD07B0561386C7EEC7271BDB9EC4852A507C1CBCC2E914FADB2DCD6DC55E64E7127C08B"
    "5A1A80F019956BA50528DCFE7691763480C69BACDBE9A56DC0A0A505BF738A11792AE87C97DA"
    "7D3FE1C1B265B50D6A692EB6DD70E4D0777AC2A10F27656418204914E67C4401F81D20D0BB27"
    "E49C1BF5AE04FBF3EE6CA8AAA2AD2FE103E02D4DBCDEE72363C33624E96EB591DC2274EDB1EB"
    "BC3AE226A0C3CA63C19661F24497CE9F5EDEE5DFD09D0F38BE8A0A7DAC1C4941DC701A595DD6"
    "738EF1BC31B2A2F2C54FA41394730C9775AC7141CC23E668C0AD6CD09A23F7639002FCC7AAA5"
    "79AEA2CA84CA02D1E1B67244DF216819059BC7308CB46EB739E448F7CB8B3BA77AA9508DC860"
    "50E596D5B636CD6C005674ABD4168E393C0B95A2A1211160F0178AFD21FE930516C3AE07083B"
    "F0C5DD5BE162BEE4D43A2AF65DDAB7F4333D779C955ED728F46FE821FB2832B1F5EB615F1D83"
    "95EE615876BA6AC09C1DA4B6118DA8756EF45114AFA8DCDD8370B0E4BC51865C6F18852797A0"
    "32F305E867591A884CE85B0D2E354CD59B8CDAA2435A69CEADEFC7398962ECF88F258FDAD4CC"
    "4E1576DEEC81D3AD5CF2DF1DEB111942B62E66928DFC3FE021AC209C6BB8B7B2F34E650E15A3"
    "029B09C90EC8FBF6598CB4BD1A4A06FF0A89FADA65ADFD0A896C0FCB80ECD637A46C00825A8E"
    "09C445D5BC0DFFED158A2F135EFEA7B7716F2311BA4C0C92B5AD085EC395D64058301D8F4092"
    "1C49F579A110E5FA0E4CB79E71613F7EE42EDE55FF3BE32C943402EF398812D42BCC308A2E1E"
    "8CB217008798A373BC9CEC87FB29F615C31CA4CEA0078D57CE4B023F950E9E8C7562A7EF422A"
    "ADB162375CC7B8B71A574CFCACE99596C4CEF7E2B0C7AB2FD1D4DC7F92FE7340C4E0DC7128EA"
    "155E2B5347960F600C2BDAC29117A2587A569ECB3F43ADEFA985C90316239C0AE5FD27F82F4D"
    "9D4878FE770120FBBB53626D0628B123E96F8AE75E67AE624DB8369586D4CACCAC65114A19C6"
    "2ED941982E73E2741EC2342108E71499F817A4BFE280E09153552A9EE780D0011E6338DF4497"
    "5CDF653036BF856EEB8957C43B2EB0704ECAA1F476C9147542903931FA79A945F7B8FB68F9B9"
    "3EA740C03A450DCAE98A0953A4CA56A25E8291C80B3F9099A8D85F3C07F3AC4FDB332ED99846"
    "76CB107988664099B1346D0393EB170E831774CDFD85C722652C2F59AF5AFEE1E393B0DA1267"
    "87225F8A21412563D04A66DF9FD788DF57A1667AAB7036542A62ED0001D1B0A0D48591A17004"
    "37791D2E6DDFA0AD21E5B45E5B8A365D4311A837DAA81D366C6D248FF94CB047BE78FFCD4A0C"
    "458BF455A4C3C027A50A72E20D3A5F7DC0C5B46B7479083EBC131B32ADF8F333521A7D80A4B7"
    "9621405F6B214BC123E0FF887017E51B97964DF8728A107ACA9801857C75B2A96844956C6AEB"
    "FA9E010AAB5172D1345753AFA549B380A8648A5DDAA0884E0776EFEE39C2334C9457C87B8AFF"
    "3B2878447AD0416A675874908464EA66782EAACAC12A0946C6251961804F7E4673859F6A4B7B"
    "F4C48393D3718B4C2DB38F4E29D07DFFB02146A117B62AF3837AFDF2D01ACD01F981E4FB8C1B"
    "0858F51C8CCCF2476339ECFD4DF9530989B92B1927A18D659F7024E46D1EB186C3DE5FCEF952"
    "5D20F735DFBD30DB73C4CE4396694FA9D8B756581CA12349B130FDDC1FA2E4C36A5C9EE43E18"
    "E854716FAFEB0191D7CD37D19CDDCC4C6551D972247347AF393C490050C50C33E5B89DAE7587"
    "79320E546BAF364817FF41B464055A44FC0A8DBE47BDD3993D699242D9AC0031DC606035CCB4"
    "546828A2898B28605ABB41644ED63E99A108CEB0A7C70854D8DFB5748C0BFF41CAD803031EF8"
    "04C816CA5C98C12FBDB921CA711818AF94C4A67CB1D821372162587A7D8D60A65F6CD059F944"
    "78922812740C33549F7C2D31D69E6AFCC0E859884173049431BD28F9E8A5BA98E07627B6D0B9"
    "345960B5C61D995FC81A86CF63564498D08972699B9FE7E6ABC50451CE5E0CC516A1C17F552E"
    "2296285049EE567DD56507B7C4428C423E7E24064AF04A8EAA0A5233B35435C4EE702F928153"
    "C441D6410321D0988FE2A7C0B88794298E30F67980B78AF4340F04290150D133CF8B154D1A93"
    "AA9D386E7CF0698652B95C192B0F31B865925D6228154501229A0866EE513F8B529B2333F7DF"
    "042A8BFA7977AB882457A5E14509CBA596DD756189E56B531E7D8AD1ED3CA21DEE128632B02E"
    "8EF23B0B2AB6E50D76A125CEAD8D52843E0A89FA86E81B337DE2786291398B71FE78CAE711C6"
    "E375345211B3DF7BF2B1AFFA6B3D8953D355190C2E0C74A972604C88F53DA683C243AB579F05"
    "CE6F35ABB354813A931DBB6151F5CE698FA7641D966E9A1E39303DF96DD0375E36F1B93C0CBF"
    "5E92A2B8D570017BC73FACCD55A528DA735CD9729A96B83D14F8BC2D5FD2ED3ED5D87CAAEAAD"
    "FD8616FAF9012EA83617E642FEEC0C9235EC6C69633DD0F2D15582820BF80907E6AD1FFD01E3"
    "D4DB130BC031C40156447B2BE5CF5D51DDB2A0FAC36244D2B31BAD8BDEF8960C087B06DC1DEE"
    "41A4D600AD7D8801922391B172372FA2DBB95CE96EB4295E199531D2C01EBF1DA2198C23E20B";

static const char CT_R2_KEY[] =
    "168C1703E79DFA60407B1E5FA94F919563A2220E8B19C14D27574225546C9D83FC3413BB5806"
    "DF8E1B6C12B7FE4EC918AEE501E7CBD64AF212C06F3C409ACC6AD07FFBB2E04DF339BAE7A7E5"
    "B6E26FAC4FB06A4DABDA250F190F2E7A43B74CD88923C7E83A585DEB9DAAE129511D318B7438"
    "5630FF2C851BA0E0FAA610073FF6035C6C0011A763C549C55CE4A0972D14240E769498A76D5F"
    "42312196FCB80F562561525018411FC0441A57C572348D612B28F5B066C9153BB296DDA95FAB"
    "AB48C3B0D2654EAE285A7D871B5FDD4DBF24A4A69C3BA2001F7BF033AD177D7548464614DE7D"
    "FCE29FFE9C85856EFD0F7305954489FA6F0EAECB22C604EC30C6E87248999FFA2C664373B182"
    "B3B68AC35A834007F820C21EB87869DB1928E49C264B2CBC9377D3BF7937F22D497C549075F8"
    "65AF8D9B25DF1EBEB17C9664D7C528977313B2A7C8DE3B01E699DB77478CDC78B49A723CD9CC"
    "FB150B39DF988EC95FE336DD6C60CF39FB9E798EA44A70E8EA6A966E2766C8481BB944A0E0E8"
    "85DD49486D1524B63EFF8C8F6AEE3BCABCEA0AC67CBD299BB00F2E4C4106A5B24C58C14F6D34"
    "528ED3E2DCE22EA21AFD56FA69E74052CCB1028B81B3CAA10B51C479FD7A2A543C451E49A36B"
    "B27B50349D16CCDC7712AF615D19CA116870067AD9A2C22B678EE1EF5C74C33A12C3A3030ACA"
    "959A3C7470F2C0B818B365E031372F24991254419ED12B15951F585EFA15B1CA4382DC4EAF6D"
    "F1898C6BDF153AD885480F4AF98C559F1E1D36C354A286A1BF3E4E79610E783FD946308513B3"
    "334E18CEF27DCFD22DBCF9436423F42C21CD6E5323EE9F1DA677764337D9195DE47E48338C09"
    "B480A01EC06C25B45276A4D1AFDFD8A5386A54B4F2284A1447F783080D34255D8AC36A674161"
    "E8B083A7369B998E61FBA4259A6AA1DA89E62148AB574AC846030133C4EF05CD019FC1F8ABAF"
    "AE0FDA52C091B4169835AAEC02FFD8D0185C22B85A9E9422ADEF4638190523229C5DCFE43FD2"
    "985513ED6B189D0FB7D4C3810BCEB92F88318CD4908A974E7D47C642EE48F2F053E52FE844FF"
    "4548CEECA4AEF09F8A0E9AC6A2F2CDE0D59BA1B20A7D690B5FAB326CE3F20CDD1DE6FD882927"
    "EE026509D4D018B77643233103E2069A2820B230341D414A202C29FED451EE84C8E34AABDC91"
    "827B7FD4DFC05EFC4128758B411482EC1AAA2FAF52B1097FA1B67F0DD976A78F8AEA0DB8AF9D"
    "2B8CB4D6D128D2443299C8AF1EDCA6DAAD7EFEF3508A7C95574253012EFA298F9428046167FC"
    "BA3539F478BBE2F809C94C121A490017C5E8AB14229483BECA63FD04C946FF4EBB2D510F7C68"
    "46859BC0AD61F6FC2501FBC6757C87FEE7D4E152DCE84769D7CAF49B571A469A3546246D9881"
    "61D50B6E39671FEDA7D779587C90B09D34C3272F9E862C0B29D2D17BD1FAF417E4C67D7237AC"
    "50ED714EF4D9D8504F3AEB71E07C0662F92BCFE81B5FDC2D19654BC0B95C6C08B0147EBFAF6C"
    "17E6BD617A8EA1563471D2CB95569CDD11B43396D124EEF709AC587459FF758793531EABD77D"
    "A26169BA7E6DF1122E5278406FFE7B6246C9E4B6FE9F25946FB2A75C5A6AD366A3205E842676"
    "2FF5B629F6F654649C1F466DF6AA6B18F186A4A11133CE7C2297D405934C6ABFA70B1615D5CF"
    "88ADE12F9DE796C8E80CE49D3E4490454CF04869C50D2DB38E57931EA9D7B862BB6EE195E2BD"
    "D0A3DDA621701A6DFCD285902D373B87C46244EF93435D0C3188387B7DF36845FC2CE59CE510"
    "6DADAB8C654C760C62FD86725330F74BC00465028E7DCD2AD9F5692368BDE28404CF9D4CFDFC"
    "D7987905EA1CF68BF0D8451F813C4AC45303ACFD0742FFF466F828EEBBE6CF7797080AD3AF42"
    "23F7A8BCA1D5A5FA911DC29D86C4DF8F5971E17047411EB27507EFD8EF5A8B191729061BD9F9"
    "4D45123C2AE1A0A89FA07FE5F2A717DE714135889D490BFFCB1E7B578605A8B6A3262E925AF2"
    "1430631A01E7B2912BC0A813850D397E0A8687284499941003E092F0F17FEBE9924FB05B5F7B"
    "49160FB8688DAD143D809BEC";

static const char CT_R2_BLOB[] =
    "7549F69F112E80952A1E2FAFF15940DDCBDBE3138C2CC39EDEA0508AA838A52DE65E534039D4"
    "C190618DAEADED28AD5F7341DC3439B97CF0CF295953CB790B0698DB1EA87762DC4A8CAE4500"
    "3AA5874FDFE50ED8F9085F06B90EC7DCB66A9DF852A7D11F18193A6B750C7BE5EF5140D6E48D"
    "B54B0ECDE9F9619C6C8621941D3520CF55B6D4AC657F545D776E482DE92593A59F414B73E089"
    "7F6A04D3ED3D180D9E61028F54E80B7C642AF384478045B080CA66B28397C9FA459A0B276743"
    "D89A059619EAB3DE40B099872A827DD970879A828FDB3CA394F92ADC30FAEED646302896F9CD"
    "E1533AAA002176E62BC67D4AC8B094A6CEBABD753992A4E0071044F9815564F3F0270F93020E"
    "7D14F31EDE258382983594143E8837CBE04E19FA4330AED27D4246A495F546F0EBE72308EB51"
    "2A6961E382EB5539D3FBC6B7C18DD39183C143D0731213BFF1BE4D39E71A80C7A405C7636C19"
    "CE7D5DF48101DDCDE04766AB5ED383FDD26F85FFD80E87CF562C91B568BA9130A099A9FA4572"
    "79D5AA3B8D47CF9256D31679B798C1D60F50D7CC0E2B30DA93C7E70A4403D3BDC6260BD8A0CD"
    "1D042ACCB049E2EBEF924027EFDFE10314A20E5CF62255BAFFC1E800F2425EA7BB5F508CDEE6"
    "7B7DC52A608960F28B8DFAF72F5DF4B4449FA88C01D764FF467EBEB8FD2D8D3742D951B3A0AC"
    "A7A07A802A2BB136D5F9BD00BC8D307F9E602406D534F65599EFC969D8BD92AA820187265E8A"
    "4A8BAA6E13EF499093B175F1357A8C774520FD209347A64B313EDA6104359989BB5028A540DE"
    "954A62C487E18C70AC65727F7AA805D5057B0FD12FC6C50AD63B0ED387CEC024C11FDEC264BC"
    "3ED02A5759FF8186A5592E12B124E9DF18FC941485B7F37DEBEFCF9DD37F90AE195DCBC11D8E"
    "1FD844A59C7308464C2624E8FCD3C1D1CAB85C231FC26D925B19F30CD9C3C8927D322BC9B1CF"
    "199A98DFFBD8C5FB19F5B14C07193C6C08B0B286F68C2BC2A316B98A065B331F7566B53240DD"
    "2039EE3AA83063D8BE59967AA9CB875F910528C60554B0A3CC132E1182FC8CC1491E26BD1F11"
    "BF87B232415FC5026977C2CEECAB99A164960C3741301D43BC9BDB0798AD98E93A805501FA52"
    "DC99C6C60B8AB870B6A5EA30055F7D0729770014BBA2A78025C730E76C4C3DA0EC7BC5AB1FD1"
    "DAC59F03FE5A6E921D30EB4E86241A3BC9A2C19802A620C417E46801472B064D92B4E9BA2058"
    "8B4762ACDE5D65DB25C26404BEAD83AB27505215498D2C1AE7ADAC92D5B087746536E3757102"
    "AD1575015FEBC100FF17DA955ACFCCB2CDFC7CC7D485B5E678044CA00584F18DC3106A663C05"
    "09B7C0CBF0C7C22DE9B02B20F4DA30322923DCAE9103B796F856DC891099743AE6F1AA8A1158"
    "D5FCEA1CA16C49BC05F365FA60D49A62F90EB95EC7AEAB0FF328DAF49E372B88986D1366F4F7"
    "35472990F0CDBB971C8AC39644190D9C99B690343602DF5FF84DB150999E9FB081A5D7CB2F9A"
    "F205B0A50C1FC4FA5F7BA21A99EDE117070CE58C11009E7CB6672BF78D5D84F18DFC0882BD36"
    "3538670734C689810644DD6C2F2F864F28A15F523CC38E8C13450D9105ED13A26FB651276990"
    "A6AD03DAB7E50BBE50D653584CA7D95593693489C02BA839B1285B1D5283EADDFA056A2947F6"
    "48C71EC21FCF4213016C7CAF6D2083205B16ABFB6ECF162D94D58ADF1C93AAFB9DD099105CAA"
    "582296B809F7577285F5973298B8F7F33B3272A100A4C08E6C95B656EC6E494B0FCAACCCD352"
    "11253FA10D14581D5178577ED8B0D727155C543E7E580E280F1048435281C90A276A55664F5E"
    "2BB176930F80C9B91DFC1B1DE814E4ECFAFB40B9277BA10EE9B04C782249280EE7258BCC5EFA"
    "65F9167943C28A98EAAFBB8C97A44F492B52182F73220447812D2C51977A39CB6C1840521C07"
    "E633D071E10BCF53224870E49AA29EC27A8668A1722E8B07372FC52220ED91F11FB4FC94D315"
    "3A9EDC6D3B71724D070A3C57DF709BDAE55BCF5E6915029E7C61765F49B2E87FFEC093EBBC01"
    "5BDC2486C6F2B05DD02FE59A569998B817C4472F12B30CFE4BA90A890CCFA8262A1DC8B2AF80"
    "931ACDC61812F0582BFB50D3682CCF7941D5B117FECEB0066F2C0BA3E99DA6B9A54249F78A80"
    "E9091D9B854F38232C11CCA987E04DBAAF01A7A4DB73785206033982CF08D5E38A7C6B19B7C1"
    "81DEFACB1B5C35F4C9B06C7B5F9C03C1A17F92F989C3208075FFD5B9E1A1970E1E71E33EAEA1"
    "CB53C29FB2D7604515FA3D63FCE638019BE5CAC0D11393DA1C42D18E52F321F54500987F7C34"
    "AF51E0B909D474C3013C4209FBCF7206914EC447BF4CC34AB18296E29A6537F9BBD0CADFDA9E"
    "57DCD7BB75E87CC281358CFB6947BD432010C91398C049FA5EBA5491969EDA3EF77BCE91F90A"
    "6144BFDFE5D1C9214638C975A803C5B7C7615A40771BE2EAB971E3EC63FF7D99B13A78BF0AA0"
    "D6C9CDCA022774E4F57EC5E83756E23C85E31A774092A8D912EA54FA7963D8B3F9A69BE80C71"
    "90A14D75786BDCFE1B6D6FD9615F7C36AA7F336DF5FCBEAA1ADAA26B66DA838B65E930F472C3"
    "FEA91171E514F5588EF3652780DFE70674407C043D1357D719DF53FC0363082BC44386D6D196"
    "87F82D4CC3DA6C54E246F61C18A0F66F177E26D64F7B4323AD7D56DFF76C7E309CE220C92EC0"
    "724AD5AE39B6A33CC58F2D9EF037680BFF1F34BF9392070338A94D5445C447A0FDCF857AFB55"
    "55FE338E4B029943F5D4BFC93F0C90416D76CE2A0DC24877585750009C77FE51BA6AFF538665"
    "7F7D6B34419C5AF93A3EF5669087169C93BF74938440BE8916ACBF596DA3330D315881A7EADE"
    "656A2846030B54122DCCB0619EF812B5F8EA8D0A3E3D82C36AF31FB8D42E140900620E6E4DC0"
    "1043560FD894EBDEFBDCA4DD664204E8C59D52AFB4345B32449FCF1C9D291F58FBA90A8FCED1"
    "7892C10D7331D60A7D2FC6264807255CF998B539030B3C5DC5B40710AA3B3707C49F4E81F84E"
    "B35973E653047133646695C3599E1845D623AEAC8CA5A52E35CDBFEE093D2886F97E3CF40F42"
    "54EE8BF3E3EF8B96B9CA4D787546CC26F56B84CE42CD4BC82AE476A285EC9BB23CE35C5F18D7"
    "95269DAFE3310D9ADF8FB0C288F92A0E8D735610E82515C64482467DB6ECE3F40A4F49439F3C"
    "5818B61680D390D372179BA13F1DB0C227E708E96713A9A0C69C7A7D3A9B60436CD1357450E5"
    "EB6EEA19586AAD97BD82713FDC92039C696B5D343764EBE0D00DFA9CC9089A4CFF73F54CEB05"
    "4CB98D69096458ACB002C7AB76188FB69F0B177E54D04C45DE4E9F2A3D2A58F293D0C33F921A"
    "CC1C91A3A5B0FF6C0540ADB593ABF05CECF339763D61AB22397197A09BFBA89622FD8F70CCE3"
    "B0B815E38C89AB397657F72DD2ED178D094B1CE97EBFDCB92100B2BBC753186E043FCA95DF32"
    "E7342BC25DDD1861622388C2E2E0E2D07E46FBB35D3DE0F054F53D8C88292B54C7354AA1E111"
    "ED7FC59861F0AC023768E16F48934D879576E7C9DEF67013238D9B88D15151A3634BCBD7EFD0"
    "546F1422299C75A2D1B7E4F731E64CBCB1E0FC3DDBBD0A102FA3B5305739D4BCFE92ED242982"
    "F0F3360E06472621AE24D606359573C058930AE528340D17BA0E4624069BD95B4D1DC1BDD917"
    "37A0C19C7E43EC452EFCC258EBCB90D92E206F8872F5486D7DC33DBF4CCBFE82C3EA3E3F1BF6"
    "A5A79D24CF54E71BB279CE14A83D7088470CD7684F69ADE69C9E5B31250F4D25AEEFDF6C5B50"
    "6C0EF7A08F55ECA3FA783DE71FCFC9567403332B1FF3A44E6ACA69F9DB9CAA06F7D85CC50672"
    "8847DDD5F2567B94959090237151CD83AA7C3BD72FF2CDC682A5FD45DEF416BB5F941B399BE3";

/* ──────────────────────────────────────────────────────────────────── */
/* Helpers                                                              */
/* ──────────────────────────────────────────────────────────────────── */

/* Decode a null-terminated ASCII hex string into a malloc'd byte buffer.
 * Returns the buffer (caller frees) and writes its length to *out_len.
 * Returns NULL on OOM or on a malformed hex string (odd length / bad char). */
static uint8_t *hex_decode(const char *hex, size_t *out_len) {
    size_t hlen = strlen(hex);
    if (hlen % 2) return NULL;
    size_t blen = hlen / 2;
    uint8_t *buf = malloc(blen);
    if (!buf) return NULL;
    for (size_t i = 0; i < blen; i++) {
        unsigned int b;
        if (sscanf(hex + i * 2, "%2x", &b) != 1) { free(buf); return NULL; }
        buf[i] = (uint8_t)b;
    }
    *out_len = blen;
    return buf;
}

/* Strip PKCS#1 v1.5 padding for either type 01 (signature) or type 02 (encryption).
 * Format: 00 <type> <PS bytes (>=8)> 00 <message>
 * Returns malloc'd plaintext (caller frees) and writes *out_len on success.
 * Returns NULL on header mismatch, missing 0x00 separator, or PS too short. */
static uint8_t *strip_pkcs1_any(const uint8_t *raw, size_t ks, size_t *out_len) {
    if (ks < 11 || raw[0] != 0x00 || (raw[1] != 0x01 && raw[1] != 0x02)) return NULL;
    int sep = -1;
    for (size_t i = 2; i < ks; i++) {
        if (raw[i] == 0x00) { sep = (int)i; break; }
    }
    if (sep < 10) return NULL;
    size_t mlen = ks - (size_t)sep - 1;
    uint8_t *m = malloc(mlen);
    if (!m) return NULL;
    memcpy(m, raw + sep + 1, mlen);
    *out_len = mlen;
    return m;
}

/* Locate <tag>...</tag> content in xml.  Returns malloc'd null-terminated string
 * with the body, or NULL if not found / OOM.  Caller frees. */
static char *xml_find_text(const char *xml, const char *tag) {
    char open[64], close[64];
    snprintf(open,  sizeof(open),  "<%s>",  tag);
    snprintf(close, sizeof(close), "</%s>", tag);
    const char *start = strstr(xml, open);
    if (!start) return NULL;
    start += strlen(open);
    const char *end = strstr(start, close);
    if (!end) return NULL;
    size_t n = (size_t)(end - start);
    char *out = malloc(n + 1);
    if (!out) return NULL;
    memcpy(out, start, n);
    out[n] = '\0';
    return out;
}

/* Parse a Chilkat-style RSA public-key XML (<Modulus>+<Exponent>, both base64).
 * Returns 0 on success and populates *n_out, *e_out (caller BN_free) and *ks_out.
 * Returns -1 on parse / decode failure. */
static int parse_pubkey_xml(const char *xml, BIGNUM **n_out, BIGNUM **e_out, int *ks_out) {
    char *mod_b64 = xml_find_text(xml, "Modulus");
    char *exp_b64 = xml_find_text(xml, "Exponent");
    if (!mod_b64 || !exp_b64) { free(mod_b64); free(exp_b64); return -1; }

    int mod_buf_len = (int)strlen(mod_b64) + 4;
    int exp_buf_len = (int)strlen(exp_b64) + 4;
    uint8_t *mod_bin = malloc((size_t)mod_buf_len);
    uint8_t *exp_bin = malloc((size_t)exp_buf_len);
    if (!mod_bin || !exp_bin) {
        free(mod_b64); free(exp_b64); free(mod_bin); free(exp_bin); return -1;
    }
    int mod_n = base64_decode(mod_b64, mod_bin, mod_buf_len);
    int exp_n = base64_decode(exp_b64, exp_bin, exp_buf_len);
    free(mod_b64); free(exp_b64);
    if (mod_n <= 0 || exp_n <= 0) { free(mod_bin); free(exp_bin); return -1; }

    *n_out  = BN_bin2bn(mod_bin, mod_n, NULL);
    *e_out  = BN_bin2bn(exp_bin, exp_n, NULL);
    *ks_out = mod_n;
    free(mod_bin); free(exp_bin);
    return 0;
}

/* Single-block raw RSA public-key exponentiation: out = ct^e mod n.
 * Writes ks bytes (zero-padded MSB) to out. */
static void rsa_pubkey_raw(const uint8_t *ct, size_t ct_len,
                            BIGNUM *n, BIGNUM *e, int ks,
                            uint8_t *out, BN_CTX *bnc) {
    BIGNUM *c = BN_bin2bn(ct, (int)ct_len, NULL);
    BIGNUM *m = BN_new();
    BN_mod_exp(m, c, e, n, bnc);
    int mlen = BN_num_bytes(m);
    memset(out, 0, (size_t)ks);
    BN_bn2bin(m, out + ks - mlen);
    BN_free(c); BN_free(m);
}

/* Unpack 6-bit values from the high bits of n input bytes (MSB-first across
 * the bit stream).  Each output byte holds one 6-bit value.
 * Returns the number of output bytes written to out (= floor(n*8/6)). */
static size_t decode_6bit(const uint8_t *in, size_t n, uint8_t *out) {
    unsigned int bit_buf = 0;
    int bit_count = 0;
    size_t op = 0;
    for (size_t i = 0; i < n; i++) {
        for (int s = 7; s >= 0; s--) {
            bit_buf = (bit_buf << 1) | ((in[i] >> s) & 1u);
            if (++bit_count == 6) {
                out[op++] = (uint8_t)bit_buf;
                bit_buf = 0;
                bit_count = 0;
            }
        }
    }
    return op;
}

/* Reconstruct the WebP image: 23 header bytes from NS_WEBP_HDR interleaved with
 * payload bytes from `input`.  The .so picks bytes from input at positions
 * {4, 5, 16, 17, 20, 21, 28} and >29; all other positions in 0..29 come from
 * the constant table.  Returns the total image size = image_count + 23. */
static size_t reconstruct_webp(const uint8_t *input, size_t image_count, uint8_t *out) {
    size_t total = image_count + 23;
    size_t table_idx = 0, input_idx = 0;
    for (size_t pos = 0; pos < total; pos++) {
        int from_input;
        if (pos > 29)                           from_input = 1;
        else if (pos == 28)                     from_input = 1;
        else if ((pos & 0x7fffffeeu) == 4)      from_input = 1;
        else if ((pos & 0x7ffffffeu) == 0x10)   from_input = 1;
        else                                     from_input = 0;
        out[pos] = from_input ? input[input_idx++] : NS_WEBP_HDR[table_idx++];
    }
    return total;
}

/* ──────────────────────────────────────────────────────────────────── */
/* Round helpers                                                        */
/* ──────────────────────────────────────────────────────────────────── */

/* Run one AES + RSA round:
 *   plain_xml = AES-CBC-256(ct1_hex, key, iv)   → contains an RSA pubkey XML
 *   plain_b64 = AES-CBC-256(ct2_hex, key, iv)   → trimmed to a base64 blob
 *   inner_xml = RSA-decrypt(b64_decode(blob), key derived from plain_xml)
 *
 * Writes the resulting RSA pubkey XML (n, e, ks) to *n_out / *e_out / *ks_out.
 * Returns 0 on success, -1 on any failure.  Caller BN_frees n/e on success. */
static int run_round(const char *ct1_hex, const char *ct2_hex,
                     const uint8_t *aes_key, const uint8_t *aes_iv,
                     BIGNUM **n_out, BIGNUM **e_out, int *ks_out,
                     BN_CTX *bnc) {
    /* Hex-decode and AES-decrypt ct1 */
    size_t ct1_len, plain1_len;
    uint8_t *ct1 = hex_decode(ct1_hex, &ct1_len);
    if (!ct1) return -1;
    uint8_t *plain1 = aes_cbc_decrypt(aes_key, aes_iv, ct1, ct1_len, &plain1_len);
    free(ct1);
    if (!plain1) return -1;

    /* Locate RSA pubkey XML inside plain1 */
    const char *end_tag = "</RSAPublicKey>";
    const char *xml_end = memmem(plain1, plain1_len, end_tag, strlen(end_tag));
    if (!xml_end) { free(plain1); return -1; }
    size_t xml_len = (size_t)(xml_end - (char *)plain1) + strlen(end_tag);
    char *xml1 = malloc(xml_len + 1);
    if (!xml1) { free(plain1); return -1; }
    memcpy(xml1, plain1, xml_len);
    xml1[xml_len] = '\0';
    free(plain1);

    /* Parse outer RSA key (used to RSA-decrypt the b64 blob) */
    BIGNUM *n_outer = NULL, *e_outer = NULL;
    int ks_outer;
    if (parse_pubkey_xml(xml1, &n_outer, &e_outer, &ks_outer) != 0) {
        free(xml1); return -1;
    }
    free(xml1);

    /* AES-decrypt ct2 → base64 blob */
    size_t ct2_len, plain2_len;
    uint8_t *ct2 = hex_decode(ct2_hex, &ct2_len);
    if (!ct2) { BN_free(n_outer); BN_free(e_outer); return -1; }
    uint8_t *plain2 = aes_cbc_decrypt(aes_key, aes_iv, ct2, ct2_len, &plain2_len);
    free(ct2);
    if (!plain2) { BN_free(n_outer); BN_free(e_outer); return -1; }

    /* Trim to base64 charset */
    size_t b64_end = 0;
    for (size_t i = 0; i < plain2_len; i++) {
        uint8_t c = plain2[i];
        if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
            (c >= '0' && c <= '9') || c == '+' || c == '/' || c == '=') {
            b64_end = i + 1;
        } else break;
    }
    char *b64_blob = malloc(b64_end + 1);
    if (!b64_blob) { free(plain2); BN_free(n_outer); BN_free(e_outer); return -1; }
    memcpy(b64_blob, plain2, b64_end);
    b64_blob[b64_end] = '\0';
    free(plain2);

    /* base64-decode */
    size_t blob_buf = (b64_end * 3 / 4) + 4;
    uint8_t *blob = malloc(blob_buf);
    int blob_n = base64_decode(b64_blob, blob, (int)blob_buf);
    free(b64_blob);
    if (blob_n <= 0) { free(blob); BN_free(n_outer); BN_free(e_outer); return -1; }

    /* Multi-block RSA decrypt with PKCS#1 strip → inner XML */
    size_t inner_len;
    uint8_t *inner = rsa_pkcs1_decrypt_multiblock(n_outer, e_outer, ks_outer,
                                                   blob, (size_t)blob_n,
                                                   bnc, &inner_len);
    free(blob);
    BN_free(n_outer); BN_free(e_outer);
    if (!inner) return -1;

    /* Locate inner pubkey XML */
    const char *iend = memmem(inner, inner_len, end_tag, strlen(end_tag));
    if (!iend) { free(inner); return -1; }
    size_t inner_xml_len = (size_t)(iend - (char *)inner) + strlen(end_tag);
    char *inner_xml = malloc(inner_xml_len + 1);
    if (!inner_xml) { free(inner); return -1; }
    memcpy(inner_xml, inner, inner_xml_len);
    inner_xml[inner_xml_len] = '\0';
    free(inner);

    int rc = parse_pubkey_xml(inner_xml, n_out, e_out, ks_out);
    free(inner_xml);
    return rc;
}

/* ──────────────────────────────────────────────────────────────────── */
/* Public API                                                           */
/* ──────────────────────────────────────────────────────────────────── */

int run_no_so_pipeline(const uint8_t *combined, size_t combined_len,
                       uint8_t **out_data, size_t *out_len) {
    if (combined_len < 1712) {
        fprintf(stderr, "[!] combined payload too short (%zu < 1712)\n", combined_len);
        return -1;
    }
    const uint8_t *buf1 = combined;
    const uint8_t *buf2 = combined + 688;

    /* Convert hardcoded key/IV hex to bytes */
    uint8_t aes_key1[32], aes_iv1[16], aes_key2[32], aes_iv2[16];
    for (int i = 0; i < 32; i++) {
        unsigned int b; sscanf(NS_AES_KEY1_HEX + i*2, "%2x", &b); aes_key1[i] = (uint8_t)b;
        sscanf(NS_AES_KEY2_HEX + i*2, "%2x", &b); aes_key2[i] = (uint8_t)b;
    }
    for (int i = 0; i < 16; i++) {
        unsigned int b; sscanf(NS_AES_IV1_HEX + i*2, "%2x", &b); aes_iv1[i] = (uint8_t)b;
        sscanf(NS_AES_IV2_HEX + i*2, "%2x", &b); aes_iv2[i] = (uint8_t)b;
    }

    BN_CTX *bnc = BN_CTX_new();
    if (!bnc) return -1;

    /* Round 1: derive RSA key #2 */
    BIGNUM *n2 = NULL, *e2 = NULL;
    int ks2;
    if (run_round(CT_R1_KEY, CT_R1_BLOB, aes_key1, aes_iv1, &n2, &e2, &ks2, bnc) != 0) {
        fprintf(stderr, "[!] Round 1 failed\n");
        BN_CTX_free(bnc); return -1;
    }
    fprintf(stderr, "[*] Round 1 → key #2 (%d-bit)\n", ks2 * 8);

    /* Round 2: derive RSA key #4 */
    BIGNUM *n4 = NULL, *e4 = NULL;
    int ks4;
    if (run_round(CT_R2_KEY, CT_R2_BLOB, aes_key2, aes_iv2, &n4, &e4, &ks4, bnc) != 0) {
        fprintf(stderr, "[!] Round 2 failed\n");
        BN_free(n2); BN_free(e2); BN_CTX_free(bnc); return -1;
    }
    fprintf(stderr, "[*] Round 2 → key #4 (%d-bit)\n", ks4 * 8);

    /* Stage A: RSA-decrypt buf2 with key #2 → 970-byte intermediate */
    uint8_t raw_a[1024];
    rsa_pubkey_raw(buf2, 1024, n2, e2, ks2, raw_a, bnc);
    BN_free(n2); BN_free(e2);
    size_t dbuf_len;
    uint8_t *dbuf = strip_pkcs1_any(raw_a, (size_t)ks2, &dbuf_len);
    if (!dbuf) {
        fprintf(stderr, "[!] Stage A: buf2 decrypt with key #2 failed\n");
        BN_free(n4); BN_free(e4); BN_CTX_free(bnc); return -1;
    }
    fprintf(stderr, "[*] Stage A: decrypted_buf2 = %zu bytes\n", dbuf_len);

    /* Stage B: build (buf1 + dbuf)[:1024], RSA-verify with key #4 → 1013 bytes */
    if (688 + dbuf_len < 1024) {
        fprintf(stderr, "[!] Stage B: not enough bytes to fill 1024-byte stack buffer\n");
        free(dbuf); BN_free(n4); BN_free(e4); BN_CTX_free(bnc); return -1;
    }
    uint8_t stack_buf[1024];
    memcpy(stack_buf, buf1, 688);
    memcpy(stack_buf + 688, dbuf, 1024 - 688);
    uint8_t raw_b[1024];
    rsa_pubkey_raw(stack_buf, 1024, n4, e4, ks4, raw_b, bnc);
    BN_free(n4); BN_free(e4); BN_CTX_free(bnc);
    size_t inner_len;
    uint8_t *inner = strip_pkcs1_any(raw_b, (size_t)ks4, &inner_len);
    if (!inner) {
        fprintf(stderr, "[!] Stage B: stack buffer verify with key #4 failed\n");
        free(dbuf); return -1;
    }
    fprintf(stderr, "[*] Stage B: inner blob = %zu bytes\n", inner_len);

    /* Stage C: assemble work = inner + dbuf[1024 - 688:] = inner + dbuf[336:] */
    size_t tail_off = 1024 - 688;
    if (dbuf_len < tail_off) {
        fprintf(stderr, "[!] Stage C: dbuf too short for tail concatenation\n");
        free(inner); free(dbuf); return -1;
    }
    size_t work_len = inner_len + (dbuf_len - tail_off);
    uint8_t *work = malloc(work_len);
    if (!work) { free(inner); free(dbuf); return -1; }
    memcpy(work,             inner, inner_len);
    memcpy(work + inner_len, dbuf + tail_off, dbuf_len - tail_off);
    free(inner); free(dbuf);

    /* Decode the working buffer.  See no_so_pipeline.py for the layout details:
     *   [0]                    control byte b0 (always 0)
     *   [b0+2 .. b0+0x42)      ECDSA signature (64 bytes, raw r||s)  — unused here
     *   [b0+0x42 .. b0+0x44)   u16 BE: input bytes for the text 6-bit decoder
     *   [b0+0x44 .. )          packed text data + length+image-info trailer */
    if (work_len < 68) { free(work); return -1; }
    size_t b0 = work[0];
    if (b0 + 0x44 > work_len) { free(work); return -1; }

    size_t text_in_count = ((size_t)work[b0 + 0x42] << 8) | work[b0 + 0x43];
    size_t data_start = b0 + 0x44;
    if (data_start + text_in_count + 8 > work_len) { free(work); return -1; }

    /* 6-bit decode the text — produces floor(text_in_count*8/6) output bytes */
    size_t text_out_max = text_in_count * 8 / 6 + 1;
    uint8_t *text_bytes = malloc(text_out_max);
    if (!text_bytes) { free(work); return -1; }
    size_t text_len = decode_6bit(work + data_start, text_in_count, text_bytes);

    /* Locate the image_count u16 — at offset (post_text_off + field_len + 6).
     * post_text_off  = data_start + text_in_count
     * field_len      = u16 BE at post_text_off (a length-prefix that we skip) */
    size_t post_text_off = data_start + text_in_count;
    size_t field_len = ((size_t)work[post_text_off] << 8) | work[post_text_off + 1];
    size_t w25 = post_text_off + field_len;
    if (w25 + 8 > work_len) { free(text_bytes); free(work); return -1; }

    size_t image_count = ((size_t)work[w25 + 6] << 8) | work[w25 + 7];
    size_t img_input_off = w25 + 8;
    if (img_input_off + image_count + 1 > work_len + 1) {
        /* Allow exactly equal — otherwise truncated. */
        if (img_input_off + image_count > work_len) image_count = work_len > img_input_off
                                                                  ? work_len - img_input_off
                                                                  : 0;
    }

    size_t img_len = image_count + 23;
    uint8_t *img = malloc(img_len);
    if (!img) { free(text_bytes); free(work); return -1; }
    reconstruct_webp(work + img_input_off, image_count, img);
    free(work);

    /* Assemble final output: [text_len:u16 BE][text][img_len:u16 BE][img] */
    size_t total = 2 + text_len + 2 + img_len;
    uint8_t *out = malloc(total);
    if (!out) { free(text_bytes); free(img); return -1; }
    out[0] = (uint8_t)((text_len >> 8) & 0xFF);
    out[1] = (uint8_t)(text_len & 0xFF);
    memcpy(out + 2, text_bytes, text_len);
    out[2 + text_len]     = (uint8_t)((img_len >> 8) & 0xFF);
    out[2 + text_len + 1] = (uint8_t)(img_len & 0xFF);
    memcpy(out + 2 + text_len + 2, img, img_len);
    free(text_bytes); free(img);

    *out_data = out;
    *out_len  = total;
    return 0;
}
