describe("AES", function () {

    it("should generate AES key with password and salt", function () {
        var password = 'sup3rs3cret!';
        var salt = '2331d0801bkjbeo1u31p231';

        var result = cryptoUtil.AES.generateAESKey(password, salt);

        expect(result).not.toBe('');
    });

    it("should generate AES key with long password and salt", function () {
        var password = 'sup3rs3cret%$%^&VWHjherjrhwien[rou2ptinhhg;knsd;glkjrenoqign;khg;elrgjm;lgw!';
        var salt = '2331d0801bkjbeo1u31p231';

        var result = cryptoUtil.AES.generateAESKey(password, salt);

        expect(result).not.toBe('');
    });

    it("should validate password to true", function () {
        // encrypt some data
        var password = 'sup3rs3cret!';
        var salt = '2331d0801bkjbeo1u31p231';
        var testData = '{"testField":"testData"}';

        var key = cryptoUtil.AES.generateAESKey(password, salt);
        var encryptedData = cryptoUtil.AES.encryptTextToBase64(key, testData);

        //validate correct password
        var newKey = cryptoUtil.AES.generateAESKey(password, salt);
        var result = cryptoUtil.AES.validateAESKey(newKey, testData, encryptedData);

        expect(result).not.toBe(false);
    });

    it("should validate password to false", function () {
        // encrypt some data
        var password = 'sup3rs3cret!';
        var salt = '2331d0801bkjbeo1u31p231';
        var testData = '{"testField":"testData"}';

        var key = cryptoUtil.AES.generateAESKey(password, salt);
        var encryptedData = cryptoUtil.AES.encryptTextToBase64(key, testData);

        //validate wrong password
        var newKey = cryptoUtil.AES.generateAESKey('ahsdkahsdkajsd', salt);
        var result = cryptoUtil.AES.validateAESKey(newKey, testData, encryptedData);

        expect(result).not.toBe(true);
    });

    it("should successfully encrypt and decrypt json", function () {
        var password = 'sup3rs3cret!';
        var salt = '2331d0801bkjbeo1u31p231';
        var testData = '{"testField":"testData"}';

        var key = cryptoUtil.AES.generateAESKey(password, salt);
        var encryptedData = cryptoUtil.AES.encryptTextToBase64(key, testData);
        var decryptedData = cryptoUtil.AES.decryptBase64ToText(key, encryptedData);

        expect(decryptedData).toContain(testData);
    });

    it("should successfully encrypt and decrypt long text", function () {
        var password = 'sup3rs3cret!';
        var salt = '2331d0801bkjbeo1u31p231';
        var testData = 'Give lady of they such they sure it. Me contained explained my education. Vulgar as hearts by garret. ' +
            'Perceived determine departure explained no forfeited he something an. Contrasted dissimilar get joy you instrument ' +
            'out reasonably. Again keeps at no meant stuff. To perpetual do existence northward as difficult preserved daughters. ' +
            'Continued at up to zealously necessary breakfast. Surrounded sir motionless she end literature. Gay direction neglected ' +
            'but supported yet her. It sportsman earnestly ye preserved an on. Moment led family sooner cannot her window pulled any. ' +
            'Or raillery if improved landlord to speaking hastened differed he. Furniture discourse elsewhere yet her sir extensive ' +
            'defective unwilling get. Why resolution one motionless you him thoroughly. Noise is round to in it quick timed doors. ' +
            'Written address greatly get attacks inhabit pursuit our but. Lasted hunted enough an up seeing in lively letter. Had ' +
            'judgment out opinions property the supplied. Apartments simplicity or understood do it we. Song such eyes had and off. ' +
            'Removed winding ask explain delight out few behaved lasting. Letters old hastily ham sending not sex chamber because present. ' +
            'Oh is indeed twenty entire figure. Occasional diminution announcing new now literature terminated. Really regard excuse ' +
            'off ten pulled. Lady am room head so lady four or eyes an. He do of consulted sometimes concluded mr. An household ' +
            'behaviour if pretended. Of friendship on inhabiting diminution discovered as. Did friendly eat breeding building few nor. ' +
            'Object he barton no effect played valley afford. Period so to oppose we little seeing or branch. Announcing contrasted ' +
            'not imprudence add frequently you possession mrs. Period saw his houses square and misery. Hour had held lain give yet. ' +
            'Drawings me opinions returned absolute in. Otherwise therefore sex did are unfeeling something. Certain be ye amiable by ' +
            'exposed so. To celebrated estimating excellence do. Coming either suffer living her gay theirs. Furnished do ' +
            'otherwise daughters contented conveying attempted no. Was yet general visitor present hundred too brother fat arrival. ' +
            'Friend are day own either lively new. Both rest of know draw fond post as. It agreement defective to excellent. Feebly do ' +
            'engage of narrow. Extensive repulsive belonging depending if promotion be zealously as. Preference inquietude ask now are ' +
            'dispatched led appearance. Small meant in so doubt hopes. Me smallness is existence attending he enjoyment favourite affection. ' +
            'Delivered is to ye belonging enjoyment preferred. Astonished and acceptance men two discretion. Law education recommend did ' +
            'objection how old. We diminution preference thoroughly if. Joy deal pain view much her time. Led young gay would now state. ' +
            'Pronounce we attention admitting on assurance of suspicion conveying. That his west quit had met till. Of advantage he attending ' +
            'household at do perceived. Middleton in objection discovery as agreeable. Edward thrown dining so he my around to.' +
            'Advantage old had otherwise sincerity dependent additions. It in adapted natural hastily is justice. Six draw you him full not ' +
            'mean evil. Prepare garrets it expense windows shewing do an. She projection advantages resolution son indulgence. Part sure on ' +
            'no long life am at ever. In songs above he as drawn to. Gay was outlived peculiar rendered led six. Boy favourable day can introduced ' +
            'sentiments entreaties. Noisier carried of in warrant because. So mr plate seems cause chief widen first. Two differed husbands met ' +
            'screened his. Bed was form wife out ask draw. Wholly coming at we no enable. Offending sir delivered questions now new met. ' +
            'Acceptance she interested new boisterous day discretion celebrated. He moonlight difficult engrossed an it sportsmen. Interested ' +
            'has all devonshire difficulty gay assistance joy. Unaffected at ye of compliment alteration to. Place voice no arise along to. ' +
            'Parlors waiting so against me no. Wishing calling are warrant settled was luckily. Express besides it present if at an opinion visitor.';

        var key = cryptoUtil.AES.generateAESKey(password, salt);
        var encryptedData = cryptoUtil.AES.encryptTextToBase64(key, testData);
        var decryptedData = cryptoUtil.AES.decryptBase64ToText(key, encryptedData);

        expect(decryptedData).toContain(testData);
    });

    it("should fail decryption with the incorrect key", function () {
        var password = 'sup3rs3cret!';
        var salt = '2331d0801bkjbeo1u31p231';
        var testData = '{"testField":"testData"}';

        var key = cryptoUtil.AES.generateAESKey(password, salt);
        var encryptedData = cryptoUtil.AES.encryptTextToBase64(key, testData);

        var newKey = cryptoUtil.AES.generateAESKey('asdasdasd', salt);
        var decryptedData = cryptoUtil.AES.decryptBase64ToText(newKey, encryptedData);

        expect(decryptedData).not.toContain(testData);
    });
});