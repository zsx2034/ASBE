package com.asbe.script;

import com.asbe.bean.*;
import com.asbe.core.SCiphertext;
import com.asbe.core.SCiphertext.CTree;
import com.asbe.core.SSetCiphertext;
import com.asbe.core.SSetPublicKey;
import com.asbe.core.SearchRet;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;

/**
 * @Author: QuanLin Du
 * @Date: 2023-09-27-14:21
 * @Description:
 */
public class ScriptEx {
    public static void OP_KEY_QUERY_NEG(SABEKey key, Pairing pairing, SSetCiphertext cipher, String attrSetName, String attrListStr){
        OP_KEY_QUERY_NEG_MAIN(cipher,key, pairing,attrSetName,attrListStr);
    }

    public static void OP_KEY_QUERY_NEG_MAIN(SSetCiphertext ciphertext, SABEKey key, Pairing pairing, String attrSetName, String attrListStr) {

            SetCipher cph = ciphertext.m_attr.get(i);
            // find a valid attribute in private key
            SearchRet ret = ciphertext.searchSetMatch(key, cph, i);
            Element ek = pairing.getGT().newElement();
            int r = ret.r;
            int rr = ret.ridx;

            if (r != -1) {
                // get info of the attribute-set in public key
                // this attribute-set is the same as the one of user's private key
                SSetPublicKey spk = (SSetPublicKey) ciphertext.m_pk;
                CSetAttribute ps = (CSetAttribute) spk.m_set.m_attrList.get(ciphertext.m_Ano[i]);
                ciphertext.m_gSet.m_attributeList = ps.m_set;
                ciphertext.m_gSet.m_size = ciphertext.m_gSet.m_attributeList.size();
                ciphertext.m_gSet.m_gList = spk.m_AF;

                // the same attribute-set in private key
                CSetElementKey eek = key.m_keyList.get(r);
                // the same attribute in private key
                CElementKey eeek = eek.m_valueList.get(rr);
                // TODO
                // restore ek
                ciphertext.decryptSetMatch(eeek, ek, cph, pairing);

                ciphertext.m_result.set(i, ek);
                ciphertext.m_flag[i] = 1;

                System.out.println("Find the match:cipher " + i + " and key " + r + " " + eek.m_strID + "-" + rr + " " + eeek.m_strID);
            } else
                ciphertext.m_flag[i] = 0;
    }

    public Element OP_AND(SCiphertext ciphertext, Pairing pairing){
        CTree tree = ciphertext.m_policy.get(0);
        CTree tree_lchild = tree.m_child.get(0);
        CTree tree_rchild = tree.m_child.get(1);
        Element r = pairing.getZr().newElement();//某一结点秘密值为r
        Element s_sub_r = pairing.getZr().newElement();//另一节点秘密值为s-r
        Element res = pairing.getZr().newElement();

        //先确认此节点是非叶子节点里的and
        if (tree.m_type == 1){
            if(tree_rchild != null && tree_lchild != null){
                r = tree_lchild.m_s;
                s_sub_r = tree_rchild.m_s;
                res = r.add(s_sub_r);
                return res;
            }else{
                return null;
            }
        } else if (tree.m_type == 1) {
            System.out.println("you should choose the operation named OP_OR.");
        }else{
            System.out.println("It's a leaf node.");
        }
        return null;
    }

    public Element OP_OR(SCiphertext ciphertext, Pairing pairing){
        CTree tree = ciphertext.m_policy.get(0);
        CTree tree_any_child = tree.m_child.get(0);
        Element res = pairing.getZr().newElement();

        //先确认此节点是非叶子节点里的or
        if (tree.m_type == 2){
            if(tree_any_child != null){
                res = tree_any_child.m_s;
                return res;
            }else{
                return null;
            }
        } else if (tree.m_type == 1) {
            System.out.println("you should choose the operation named OP_AND.");
        }else{
            System.out.println("It's a leaf node.");
        }
        return null;
    }

    public static Element OP_DECRYPT(Element main_cipher, Element main_key, Element data, int b,Element ts,Element tw,Pairing pairing) {
        Element ek = pairing.getGT().newElement();
        if (b != 0) {

            ts.set(pairing.pairing(main_key, main_cipher));
            tw.set(ts.duplicate().div(data));
            ek.set(tw);
        } else {
            System.out.println("Decryption Reconstruction Failure!");
            ek.setToZero();
        }
        return ek;
    }

    //public static SCiphertext P_DEC_ATTR_PST();
}
