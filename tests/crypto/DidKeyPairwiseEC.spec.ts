import DidKey from '../../lib/crypto/DidKey';
import { KeyType } from '../../lib/crypto/KeyType';
import { KeyUse } from '../../lib/crypto/KeyUse';
import WebCrypto from 'node-webcrypto-ossl';
const pairwiseKeys = require('./Pairwise.EC.json');

const crypto = new WebCrypto();

describe('DidKey Pairwise keys EC', () => {

  describe('Test Pairwise key generation', () => {
    it('Test P-256', (done) => {
      const alg = { name: 'ECDSA', namedCurve: 'P-256', hash: { name: 'SHA-256' } };

      // Generate the key pair
      let didKey = new DidKey(crypto, alg, KeyType.EC, KeyUse.Signature, null, true);

      didKey.jwkKey.then((ecKey1) => {
        expect(ecKey1).not.toBeNull();
        expect('P-256').toBe(ecKey1.crv);
        expect('EC').toBe(ecKey1.kty);
        done();
      })
      .catch((err) => {
        fail(`Error occured: '${err}'`);
      });

    });

    let seed = Buffer.from('xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi');
/*
    let pairwiseKeys: {pwid: string, inx: number, key: string}[] = [
      { pwid: 'peerid-0', inx: 0, key: 'pWKivj0j2FGXbKO-ET7EY0jeUgtUv7ERleZ-BxJta_Q' },
      { pwid: 'peerid-1', inx: 1, key: 'Cs5abc9y89BPQMv3UjsEVRu9ejc5yMlaDjnY26LGQFY' },
      { pwid: 'peerid-2', inx: 2, key: '3NkPrg5hjI8nLo44dMS8rAVI3CG1h_g_DNwGYdUxfp4' },
      { pwid: 'peerid-4', inx: 3, key: 'M7WGYc1P2ICW890HEFn7LuR58zR4BQD5n9pXjBOETCc' },
      { pwid: 'peerid-5', inx: 4, key: 'kYfrLuyRQhvXYo2Ym8pFVO7pe8kdxhTIGR4y6cTLaew' },
      { pwid: 'peerid-6', inx: 5, key: 'PMhhBrw9LAsYS34DCDFnxeG5eI0noOW8dJbhNW8jZR4' },
      { pwid: 'peerid-7', inx: 6, key: 'aoKDyrnQEwWLTvUlEgnvsaVm-yW8LfvaFRP51Rpo1d8' },
      { pwid: 'peerid-8', inx: 7, key: 'sPGK4xCGBmhjTGVSxzgTNTEr54gHtbTzWRhAHE0YQGY' },
      { pwid: 'peerid-9', inx: 8, key: 'jWHSkVVAx5ASBGevjB6Y8WK1WCtvMyK8ThUdynPXtQ8' },
      { pwid: 'peerid-10', inx: 9, key: 'qKRsC7UkrM82gXZCW4oAeZnJJj7ASFJQkgrK8ppGzxc' },
      { pwid: 'peerid-11', inx: 10, key: 'khQkCDzMCLCbt_h5trtLLpLUJry0sh25KeChnlM01po' },
      { pwid: 'peerid-12', inx: 11, key: 'PtGYq1ZcS9LQrqZXAihv6SfCTyxbCKZOq4geiR38JOA' },
      { pwid: 'peerid-13', inx: 12, key: 'xkSbImLPz0ptEBHE7hZNOyZrSmO2sCgWq7ZtL8Jkvc8' },
      { pwid: 'peerid-14', inx: 13, key: 'ql0rreYY_F27K-bR4pWqQvczEO1yp75WfIlwra5SeLQ' },
      { pwid: 'peerid-15', inx: 14, key: '2tkVT4rB3MFHktAzIEjvNSlGM0_OZ7KQYNjUR3_IyX0' },
      { pwid: 'peerid-16', inx: 15, key: 'SgBbsLGn3luKPFDrUAejsr0nfMTdt-LsXv0zZ_9Xs4E' },
      { pwid: 'peerid-17', inx: 16, key: 'nX7mvv_Kn3qjQdvZSSf5agy_IVG3y1Z-zwy9EHjRNww' },
      { pwid: 'peerid-18', inx: 17, key: '3F-oe4-0wVh_7lADAL0UZvBUMkseGAQBGD-4ehuvBvo' },
      { pwid: 'peerid-20', inx: 18, key: 'rblKHssJu9Z0voQs1UK3XN46leQZ8dd1jWWNqSPtJCw' },
      { pwid: 'peerid-3', inx: 19, key: 'LlyQFlcgAyGMGzkv8_Vs4uMY1sG2Kwqz1vn1AHlqIl4' },
      { pwid: 'peerid-21', inx: 20, key: 'VwgrEYsMB3xJs9CFZHPEBiFc8L6xlmh40iMO5KIx6Bo' },
      { pwid: 'peerid-23', inx: 21, key: 'K0G93E2Nqbo5-glvBZJ_IBPHMR8-UxyyvbJaz_tsOFE' },
      { pwid: 'peerid-22', inx: 22, key: 'heXfLXiDJFrmeQq4YPygqOkvV75jjdDOsbgDaH81gg4' },
      { pwid: 'peerid-24', inx: 23, key: 'fXSSfbgM1Z78EqRQpj0xz-XSoCK46oH4iMd1JW-kaYc' },
      { pwid: 'peerid-25', inx: 24, key: 'YRBhc0_L31c9SwNJRJ2hCPfjq9LRGxQpIo_D7xaNzTk' },
      { pwid: 'peerid-26', inx: 25, key: 'FYUjaEuEnuaJGnRce5wY8zAgEILwu-5CDzvE4VjZKIE' },
      { pwid: 'peerid-27', inx: 26, key: '6nGJUihawRsILu3RcsPZq6RCkckxzjtoJQwwauPUbA0' },
      { pwid: 'peerid-28', inx: 27, key: 'kzX_1eYBWNqBpq6-W_HAq-z5LOeY3aBq80bxHl-zXYw' },
      { pwid: 'peerid-29', inx: 28, key: 'B3oJMjEW6W37K9HXLAAfQcWnKEH-Np7jWMmWv6wv804' },
      { pwid: 'peerid-30', inx: 29, key: 's-iYtgb4-VwE7yHLqDFFyuA0s94EARJvBpqUjGg8Izk' },
      { pwid: 'peerid-31', inx: 30, key: 'RNElPT7X26XeR2VG_Llih7VVm6nrGtnVC-li3hEqcfE' },
      { pwid: 'peerid-32', inx: 31, key: 'Cs_SpJP98qNOLJLn-BfTcM4wQ0WmBjbXuilbPTCqkb4' },
      { pwid: 'peerid-33', inx: 32, key: 'WitaRk-I_7GTEMHuUi4aVxFxBApBOhm9Rn5E-GETYlY' },
      { pwid: 'peerid-34', inx: 33, key: 'OFPWhFiPNcNK8cFTZo61a7eTEbU645H7n0nWTmUQbP4' },
      { pwid: 'peerid-35', inx: 34, key: 'rSFVZa3trSB_WwYGMFaa_QFKyigG4kiCOrrUO4t5Mm4' },
      { pwid: 'peerid-36', inx: 35, key: 'i9u7aEo_SvNwnno_4CkHkFgxov7A52zPji9GsyhvRJs' },
      { pwid: 'peerid-37', inx: 36, key: 'egTaXivftc1T8ShF939xCILuQl6hFAgFOVqMozg2tPc' },
      { pwid: 'peerid-38', inx: 37, key: '-w5Az5QMUscW1F1U42RJh4HRyNdXGe8nTE8euXweELc' },
      { pwid: 'peerid-39', inx: 38, key: '0kNl4_S-BWr4n2XZoD5g88orljzwVrFBMwCJFJicp4Q' },
      { pwid: 'peerid-40', inx: 39, key: 'gspD7BhNILp48yNpu1EPLjtcRS96_XBVJTUKNkuOAK8' },
      { pwid: 'peerid-41', inx: 40, key: '-meLcZBcSS0bCGo-Y9jI6ThQiQWmqfRij6Wp5clyOgY' },
      { pwid: 'peerid-43', inx: 41, key: 'df7_EgNXI957v3sjLHNunwHpzy0Mlvpe9DkuMjh1Ids' },
      { pwid: 'peerid-44', inx: 42, key: 'ZH4s0fE3FNYAj6sKl1Hanrb3rrJSh1j8a_zut5_oKDM' },
      { pwid: 'peerid-45', inx: 43, key: 'nU_77EA7wHTvrmAk1Snsp3bKPgGE_Fet8wNAZ-cPcf8' },
      { pwid: 'peerid-46', inx: 44, key: 'n8D7H9nv579AGqYAP0lDapq2A6ZBWGYhrcl1EDHKLT4' },
      { pwid: 'peerid-47', inx: 45, key: 'Is4Y4D4QAMPjzERyTbVwFvUADPaC0KT2Z_I7grvztSA' },
      { pwid: 'peerid-48', inx: 46, key: 'f0PhmST4IiWbshcO5i-JkqV3yEprY3jsm-de80CbPFo' },
      { pwid: 'peerid-49', inx: 47, key: 'zSALe1w6v61qBjBMHuXRGUKqHDISWscGw7Y01GIwULU' },
      { pwid: 'peerid-50', inx: 48, key: '4OBtZzn4WRspzNVy_XtuhEYsdgj8BIDfXrZJbXjvKQ8' },
      { pwid: 'peerid-42', inx: 49, key: 'NG6NDqdk3p3zCeozuKOJVi8IeQBU21DNB8du1Uf1KrM' },
      { pwid: 'peerid-51', inx: 50, key: 'qe_mS3hr-evA6oMcIivNdGGh3oEZMNfJsox-a6BMuAo' },
      { pwid: 'peerid-52', inx: 51, key: 'R07x-CNTj0rE6LUzQJhx4bcBX4sKF_JEDV0wsuP50v0' },
      { pwid: 'peerid-53', inx: 52, key: '1X5orlEfpsV6RximCbXLkrhg6rH3A-ubNeilkjs4Bmk' },
      { pwid: 'peerid-54', inx: 53, key: 'mH9X4A8ttzeOVxUZvSJlFt1xCodS9lXXsTHoF9-Y0HU' },
      { pwid: 'peerid-55', inx: 54, key: 'rrsGFSt0g2Auuldbno6WyPEKR26XhOxBLBPndSIP-T4' },
      { pwid: 'peerid-56', inx: 55, key: '1Qde7EqTZNp4k1BKHzx70bhlDYos6kLD1apjYU4pwaQ' },
      { pwid: 'peerid-58', inx: 56, key: '4o6gLtvCLI2LQTUaMg4OiRPxzpLFkjNhNU8h4jcoDNQ' },
      { pwid: 'peerid-57', inx: 57, key: 'fNQ_RIV-nj8oVtfKpsSIFoEj34Nn09e3Y9j1QE9Y1ts' },
      { pwid: 'peerid-60', inx: 58, key: 'CkzsW7sFpXhGyRjTbskEyORBeSc92Li62KnNlEY0bAM' },
      { pwid: 'peerid-59', inx: 59, key: '3PT4TgzmOWz53dSwu_RghvYgpWAxSGVtbascTknjkuU' },
      { pwid: 'peerid-61', inx: 60, key: 'htXUlvUJpqS0zXIgpWfgu2I0f75CqE9tceG6nZLSKXQ' },
      { pwid: 'peerid-19', inx: 61, key: 'LxC5NabUlx9taHePLJz4spHxiwvx_dxts2jdlihMe2E' },
      { pwid: 'peerid-62', inx: 62, key: 'fV0JpjPQH5SG358B2mPaGo7V8Iw7NEaufx1yCEQVP5o' },
      { pwid: 'peerid-63', inx: 63, key: 'qhW3wwtra4DSxGauRScsz-aipMGEvO6njE31_Z_lF5Y' },
      { pwid: 'peerid-64', inx: 64, key: '9eJOBHmaqwgEsFRxJiYbaZ13IixKN9HzWp4IwfTU0OI' },
      { pwid: 'peerid-65', inx: 65, key: 'uLCYmWWF8WFIbDdaMNwIYBvW_4vmBeG0kXF3917uwR0' },
      { pwid: 'peerid-66', inx: 66, key: 'ZZmnUoXl7Vlbv0aqgWUmOubL5UH-s7YVsKaQwlTkLK0' },
      { pwid: 'peerid-67', inx: 67, key: 'G5hK63UI1G4xfHgDPtpoXBlxtP66EOuDFJLbPNwkn34' },
      { pwid: 'peerid-68', inx: 68, key: 'y_Pj-5jWQpgyiM7NMpwuo6Mcs5L4502tt1cd0tLJqYY' },
      { pwid: 'peerid-69', inx: 69, key: '40lu1zYZd0M7YTW31So62JwHzVv2kZPMCAxSI97cHGQ' },
      { pwid: 'peerid-70', inx: 70, key: 'm40SjcOA391ViLet4M8cB3ax6-a_LvwwMavowZZvxnI' },
      { pwid: 'peerid-71', inx: 71, key: 'QmQkMgMVjhviFBXQrN99SqIoteXZLGF_XBCuglRqP3s' },
      { pwid: 'peerid-72', inx: 72, key: '6ytaR-cYNQj3tpILWcuPKR-Nqw4JkzdjjSKu2IkG50Y' },
      { pwid: 'peerid-73', inx: 73, key: '--fe_aBszkQ4A-hCcIjA7dbdxP3OeJYtYE4GR9g_TD4' },
      { pwid: 'peerid-74', inx: 74, key: 'MenCC5jys_AovvIXioX8NkWpGTvNJIrz7MFvJ5mWBh8' },
      { pwid: 'peerid-75', inx: 75, key: 'T8K4l_P6Z1ckJLL2Nm0-5rTTqbLriF3fTy-U-ldd-_Y' },
      { pwid: 'peerid-76', inx: 76, key: 'z0Q38au95DhQHjQKoW0uj26R0s9yBQ_MGOdz28mFefQ' },
      { pwid: 'peerid-77', inx: 77, key: 'ZJSvz1RTvFQkrXkTspSUw8hfxELqnhlNfDdWqDmT9qE' },
      { pwid: 'peerid-79', inx: 78, key: '4HAETI1Llf1n8_BLTyJQEPTZXIAsGnLRRvsa43AXYNg' },
      { pwid: 'peerid-78', inx: 79, key: '-P3tqJXUxO9IjYxnz4nCZQRNykL1iWGyy0RdYvFdU_U' },
      { pwid: 'peerid-80', inx: 80, key: 'Ykf5KboBShsEri98VWxd96XwH2UgeAzf1y0p1B9tC44' },
      { pwid: 'peerid-81', inx: 81, key: 'aqmm0OGXTWKF5arkx_if0eQE8EoJwIQveZRFiEL7SAs' },
      { pwid: 'peerid-82', inx: 82, key: 'Z_7gdgHzA2y5_lnzufcBbaePmsAqblZ1DAd4YFVbDag' },
      { pwid: 'peerid-83', inx: 83, key: 'XCUzt38BmVJ9Z1oigvuaLDi5MSycFfh0TFxhjybdYHk' },
      { pwid: 'peerid-84', inx: 84, key: 'R-IGTcIVrEsAd0fZ_YLm2k9crP-7gBRTK1I6B6JnOrs' },
      { pwid: 'peerid-85', inx: 85, key: 'UMp71hA4njywZs1gpS3VHzRHQ1j05bPUXhmTPQjee_Q' },
      { pwid: 'peerid-86', inx: 86, key: 'ixjKHkzsoeM68Ufs1GYr8xMY0OcsNUM2709jhZmnkjU' },
      { pwid: 'peerid-87', inx: 87, key: 'xUIRePCK88TLP7PWNUo4KY5jn70mcIBCf01odD6PyII' },
      { pwid: 'peerid-88', inx: 88, key: '8ubmrohbXhoeCbapCj2gwM7tb-LDfCjBKaLqc6bhPqE' },
      { pwid: 'peerid-90', inx: 89, key: 'MNYaZ6CLwltycNK3uJ20HtjpHqCGbJ340rAZ0RXt65E' },
      { pwid: 'peerid-91', inx: 90, key: 'I5a_V2GOOrTNQKIlf3Y7gXjy603RCohADM3ftiNn5XM' },
      { pwid: 'peerid-89', inx: 91, key: 'AQLO8nXqFbz_ifnXs-DRnSNuEGeXCeowWp-iG3xy2Dc' },
      { pwid: 'peerid-92', inx: 92, key: 'uueNyb1IiNIGjttAEnDilhqCn9xNQz765zxYNwLkSSs' },
      { pwid: 'peerid-95', inx: 93, key: '7sOY9BSoSsGa_sNlei_2GalKg4Zvkyvz8AqplNXhp7g' },
      { pwid: 'peerid-93', inx: 94, key: '4ea9gDLzA3HhPFBHewGxWJCFcw1083ZXSYj1M_zth74' },
      { pwid: 'peerid-96', inx: 95, key: 'Lqnm9Qba2A4WjHWnpwjwRp5RGRpFEHprJ-XYXoq7D30' },
      { pwid: 'peerid-94', inx: 96, key: 'djaYx-6YjW9l2dLr1ko-dQPbLh7bCMWjLJ_Wj8Nnvyo' },
      { pwid: 'peerid-97', inx: 97, key: 'UPHOzPEzug5i0KWDBVDVguzQkfIG9GmeuvWFZt7i4rA' },
      { pwid: 'peerid-98', inx: 98, key: 'Zh84KpZ_cUD4d309NABzrSDzjOEDB5_nsytfFjbAuak' },
      { pwid: 'peerid-99', inx: 99, key: 'OkGQJ3DbhhbP_TAK0nQVuUE09VEROtP_pfBZvvvbzdE' }
    ];
*/
    it('Check PairwiseId generation uniqueness', () => {
      let inx: number = 0;
      let results: string[] = [];
      const alg = { name: 'ECDSA', namedCurve: 'P-256K', hash: { name: 'SHA-256' } };
      let didKey: DidKey = new DidKey(crypto, alg, KeyType.EC, KeyUse.Signature, null);
      for (inx = 0 ; inx < 1000; inx++) {
        didKey.generatePairwise(seed, `did=${inx}`, 'peer').then((pairwiseKey: DidKey) => {
          pairwiseKey.jwkKey.then((jwk) => {
            results.push(jwk.d);
            // console.log(`Check ${jwk.d} ${results.length}`);
            expect(1).toBe(results.filter(element => element === jwk.d).length);
          })
          .catch((err) => {
            fail(`Error occured: '${err}'`);
          });
        })
        .catch((err) => {
          fail(`Error occured: '${err}'`);
        });
      }
    });

    it('Check PairwiseId generation uniqueness with different seed', (done) => {
      let inx: number = 0;
      let nrIds: number = 100;
      let ids: string[] = [];
      for (inx = 0; inx < nrIds; inx++) {
        ids.push(`peerid-${inx}`);
      }

      let did: string = 'abcdef';
      let seed = Buffer.from('yprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi');
      const alg = { name: 'ECDSA', namedCurve: 'P-256K', hash: { name: 'SHA-256' } };
      let didKey: DidKey = new DidKey(crypto, alg, KeyType.EC, KeyUse.Signature, null);
      inx = 0;
      for (let pwid of ids) {
        didKey.generatePairwise(seed, did, pwid).then((pairwiseKey: DidKey) => {
          pairwiseKey.jwkKey.then((jwk) => {
            // console.log(`{ pwid: '${pwid}', inx: ${inx++}, key: '${jwk.d}'},`);
            pairwiseKeys.forEach((element: any) => {
              if (element.pwid === pwid) {
                // console.log(`Check ${element.inx}: ${element.key} == ${jwk.d}`);
                expect(element.key).not.toBe(jwk.d);
                expect(0).toBe(pairwiseKeys.filter((element: any) => element === jwk.d).length);
                return;
              }
            });
          })
          .catch((err) => {
            fail(`Error occured: '${err}'`);
          });
        })
        .catch((err) => {
          fail(`Error occured: '${err}'`);
        });
      }

      done();
    });

    it('Check PairwiseId generation uniqueness with different peer', (done) => {
      let inx: number = 0;
      let nrIds: number = 100;
      let ids: string[] = [];
      for (inx = 0; inx < nrIds; inx++) {
        ids.push(`peerid--${inx}`);
      }

      let did: string = 'abcdef';
      const alg = { name: 'ECDSA', namedCurve: 'P-256K', hash: { name: 'SHA-256' } };
      let didKey: DidKey = new DidKey(crypto, alg, KeyType.EC, KeyUse.Signature, null);
      inx = 0;
      for (let pwid of ids) {
        didKey.generatePairwise(seed, did, pwid).then((pairwiseKey: DidKey) => {
          pairwiseKey.jwkKey.then((jwk) => {
            // console.log(`{ pwid: '${pwid}', inx: ${inx++}, key: '${jwk.d}'},`);
            pairwiseKeys.forEach((element: any) => {
              if (element.pwid === pwid) {
                // console.log(`Check ${element.inx}: ${element.key} == ${jwk.d}`);
                expect(element.key).not.toBe(jwk.d);
                expect(0).toBe(pairwiseKeys.filter((element: any) => element === jwk.d).length);
                return;
              }
            });
          })
          .catch((err) => {
            fail(`Error occured: '${err}'`);
          });
        })
        .catch((err) => {
          fail(`Error occured: '${err}'`);
        });
      }

      done();
    });

    it('Check PairwiseId generation uniqueness with different did', (done) => {
      let inx: number = 0;
      let nrIds: number = 100;
      let ids: string[] = [];
      for (inx = 0; inx < nrIds; inx++) {
        ids.push(`peerid-${inx}`);
      }

      let did: string = 'abcdef';
      let seed = Buffer.from('yprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi');
      const alg = { name: 'ECDSA', namedCurve: 'P-256K', hash: { name: 'SHA-256' } };
      inx = 0;
      let didKey: DidKey = new DidKey(crypto, alg, KeyType.EC, KeyUse.Signature, null);
      for (let pwid of ids) {
        didKey.generatePairwise(seed, did, pwid).then((pairwiseKey: DidKey) => {
          pairwiseKey.jwkKey.then((jwk) => {
            // console.log(`{ pwid: '${pwid}', inx: ${inx++}, key: '${jwk.d}'},`);
            pairwiseKeys.forEach((element: any) => {
              if (element.pwid === pwid) {
                // console.log(`Check ${element.inx}: ${element.key} == ${jwk.d}`);
                expect(element.key).not.toBe(jwk.d);
                expect(0).toBe(pairwiseKeys.filter((element: any) => element === jwk.d).length);
                return;
              }
            });
          })
          .catch((err) => {
            fail(`Error occured: '${err}'`);
          });
        })
        .catch((err) => {
          fail(`Error occured: '${err}'`);
        });
      }

      done();
    });

    it('Check PairwiseId generation', (done) => {
      let inx: number = 0;
      let nrIds: number = 100;
      let ids: string[] = [];
      for (inx = 0; inx < nrIds; inx++) {
        ids.push(`peerid-${inx}`);
      }

      let did: string = 'abcdef';
      const alg = { name: 'ECDSA', namedCurve: 'P-256K', hash: { name: 'SHA-256' } };
      let didKey: DidKey = new DidKey(crypto, alg, KeyType.EC, KeyUse.Signature, null);
      inx = 0;
      for (let pwid of ids) {
        didKey.generatePairwise(seed, did, pwid).then((pairwiseKey: DidKey) => {
          pairwiseKey.jwkKey.then((jwk) => {
            // console.log(`{ pwid: '${pwid}', inx: ${inx++}, key: '${jwk.d}'},`);
            pairwiseKeys.forEach((element: any) => {
              if (element.pwid === pwid) {
                // console.log(`Check ${element.inx}: ${element.key} == ${jwk.d}`);
                expect(element.key).toBe(jwk.d);
                return;
              }
            });
          })
          .catch((err) => {
            fail(`Error occured: '${err}'`);
          });
        })
        .catch((err) => {
          fail(`Error occured: '${err}'`);
        });
      }

      done();
    });

  });
});
