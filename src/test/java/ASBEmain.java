import com.asbe.core.*;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;

import java.util.Scanner;

import com.asbe.bean.CElementKey;
import com.asbe.bean.CElementOfSet;
import com.asbe.bean.CSetAttribute;
import com.asbe.bean.CSetElementKey;
import com.asbe.bean.GenTreeRes;
import com.asbe.bean.SetCipher;
import com.asbe.bean.Type;

public class ASBEmain {
    public static void generateSetCipher(SSetCiphertext cipher, SSetAttributeList attr, Pairing pairing) {

        System.out.println("Please set the conditions on attribute:");

        int n;
        Scanner scanner = new Scanner(System.in);

        System.out.println("Set the sum number of Conditions:");
        n = scanner.nextInt();
        cipher.initialSize(n, pairing);

        for (int i = 0; i < n; i++) {

            System.out.println("<" + i + ">" + "Selecet attribute from (0 to " + (attr.m_attrList.size() - 1) + ")");
            int k = scanner.nextInt();

            if (k > attr.m_attrList.size()) continue;
            cipher.m_Ano[i] = k;

            CSetAttribute s = (CSetAttribute) attr.m_attrList.get(k);
            System.out.println("Attribute " + k + ": Name[" + s.m_attrname + "].");

            System.out.println("Please input operation type(0:ALL, 1:INCLUDE, 2:EXCLUDE):");
            int input = scanner.nextInt();

            if (input == 0) {
                s = (CSetAttribute) attr.m_attrList.get(k);
                SetCipher set = new SetCipher();
                set.subset = new Boolean[n];
                set.m_type = Type.ALL;
                cipher.m_attr.add(set);
            } else {

                s = (CSetAttribute) attr.m_attrList.get(k);
                int count = s.m_set.size();

                SetCipher set = new SetCipher();
                set.subset = new Boolean[count];

                if (input == 1) set.m_type = Type.INCLUDE;
                else if (input == 2) set.m_type = Type.EXCLUDE;

                cipher.m_attr.add(set);

                for (int j = 0; j < count; j++) {

                    CElementOfSet e = s.m_set.get(j);

                    System.out.println("Element " + j + ":" + e.m_Aset + ", please make sure whether it is in cipher (1 or 0):");

                    int con = scanner.nextInt();
                    String ss = e.m_Aset;

                    set.subset[j] = false;

                    if (con == 1) {

                        set.ElementsOfSet.add(ss);
                        set.subset[j] = true;
                    }
                }

                System.out.println("number of element set:" + set.ElementsOfSet.size());
                cipher.m_attr.set(i, set);

            }

            System.out.println("===========================");
            for (int ii = 0; ii < cipher.m_attr.size(); ii++) {

                SetCipher pset = cipher.m_attr.get(ii);
                int kk = pset.ElementsOfSet.size();

                CSetAttribute s1 = (CSetAttribute) attr.m_attrList.get(cipher.m_Ano[ii]);

                switch (pset.m_type) {
                    case ALL:
                        System.out.println("Condition C" + ii + ": " + s1.m_attrname + " have all elements.");
                        break;
                    case INCLUDE:
                        System.out.println("Condition C" + ii + ": " + s1.m_attrname + " include " + kk + " elements.");
                        break;
                    case EXCLUDE:
                        System.out.println("Condition C" + ii + ": " + s1.m_attrname + " exclude " + kk + " elements.");
                        break;
                }

                for (int j = 0; j < kk; j++) {
                    System.out.println("Element " + j + " : " + pset.ElementsOfSet.get(j));
                }
            }
        }

        System.out.println("==========================");
        System.out.println("Please input logical equation (e.g.,(C0 and C1 and (C2 or C3)))");

        Scanner strScanner = new Scanner(System.in);
        char[] str = new char[100];
        str = strScanner.nextLine().toCharArray();
        GenTreeRes res = new GenTreeRes();
        res.tree = null;
        res.control = 0;

//		System.out.println("str length = "+str.length);

        cipher.m_policy.add(0, cipher.genTree(res, str, 0, str.length).tree);

        System.out.print("The logical equation is:");
        cipher.printTree(cipher.m_policy.get(0));
        System.out.println();

    }


    public static void generateSetKey(SASBEKey key, SSetAttributeList attr) {

        System.out.println("Please set attribute key properties:");

        int n = attr.m_attrList.size();
        Scanner scanner = new Scanner(System.in);

        for (int i = 0; i < n; i++) {

            CSetAttribute s = (CSetAttribute) attr.m_attrList.get(i);
            System.out.println("Attribute " + i + ": Name[" + s.m_attrname + "]");
            System.out.println("Please set this attribute(e.g.,0:null, 1:set)");

            int b = scanner.nextInt();

            if (b == 1) {

                CSetElementKey ekey = new CSetElementKey();

                int count = s.m_set.size();
                ekey.m_index = i;
                ekey.m_strID = s.m_attrname;

                for (int j = 0; j < count; j++) {

                    CElementOfSet e = s.m_set.get(j);
                    System.out.println("element " + j + ": " + e.m_Aset + ", please make sure whether it is in sk (1 or 0)");
                    int con = scanner.nextInt();
                    String ss = e.m_Aset;

                    if (con == 1) {

                        CElementKey ee = new CElementKey();
                        ee.m_Aindex = j;
                        ee.m_strID = ss;
                        ekey.m_valueList.add(ee);
                    }
                }

                key.m_keyList.add(ekey);
                System.out.println("We have set this element.");
            } else {

                System.out.println("We have not set this attribute.");
            }
        }
    }

    public static void main(String[] args) {

        String curvePath = "a.properties";
        AttributeSetBasedEncryption asbe = new AttributeSetBasedEncryption(false, curvePath);
        asbe.setup();

        SSetCiphertext ciph = new SSetCiphertext();
        generateSetCipher(ciph, asbe.m_pk.m_set, asbe.getPairing());

        Element ek = asbe.getPairing().getGT().newElement();
        asbe.encrypt(ciph, ek);

        System.out.println("Encrypt ek: " + ek);

        SASBEKey sk = new SASBEKey();

        generateSetKey(sk, asbe.m_pk.m_set);
        asbe.genKey(sk);

//        ScriptProcessor.generateScript(ciph, asbe);
        StringBuilder stringBuilder = new StringBuilder();
        ScriptProcessor1.generateScript(ciph, asbe, stringBuilder);
        System.out.println(stringBuilder);

        Element ee = asbe.getPairing().getGT().newElement();
        asbe.decrypt(ciph, sk, ee);

        System.out.println("Decrypt ek: " + ee);

        if (ee.equals(ek)) {
            System.out.println("Decryption Success!");
        } else {
            System.out.println("Decryption Failure!");
        }

    }
}
