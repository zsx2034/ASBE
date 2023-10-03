/*
 * SCiphertext.java
 * C程序改动：
 * CTree定义为SCiphertext内部类
 * genTree()增加返回值类型GenTreeRes 存储tree(CTree),control(int)
 * */
package com.asbe.core;

import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;

import java.util.ArrayList;
import java.util.List;

import com.asbe.bean.GenTreeRes;
import com.asbe.bean.PublicKey;
import com.asbe.bean.SABEKey;
import com.asbe.bean.SAttributeList;

public class SCiphertext {

    //内部类CTree 参数表示树结构
    public class CTree {
        int m_type;      //type 0:叶子节点 1:and  2:or
        int m_cno;       //Condition Number
        Element m_data;  //存储重构数据
        Element m_s;     //存放密码数据
        int m_flag;     //标记重构中是否已经使用  1：未用（编译错误）
        List<CTree> m_child;  //孩子

        public CTree() {

            m_child = new ArrayList<CTree>();
        }

        public boolean isLeaf() {
            return m_type == 0;
        }

        public boolean isLogicAnd() {
            return m_type == 1;
        }

        public boolean isLogicOr() {
            return m_type == 2;
        }
    }

    /*
     * SCipher 成员变量
     * */
    public Element m_r;      //保密参数，用于调试
    public List<Element> m_w;        //share of secrets from tree's LSSS
    public int m_count;
    public Element m_main;   //主密文
    public List<Element> m_result;   //用于解密
    public int[] m_Ano;  //属性号
    public int[] m_flag;  //处理标记
    public List<CTree> m_policy;


    public SCiphertext() {
        m_w = new ArrayList<Element>();
        m_result = new ArrayList<Element>();
        m_policy = new ArrayList<CTree>();

    }
    /*
     * 私有成员函数
     * 用于用户录入字符串的处理
     * */

    /*
     * 寻找用户输入属性字符串的末位
     * 括号匹配（录入格式正确）返回末位index
     * 括号不匹配返回-1
     * */
    private int findEnd(char[] str, int begin, int end) {

        int sum = 0;
        int i = begin;

        while (i <= end) {
            if (str[i] == '(')
                sum++;
            if (str[i] == ')')
                sum--;
            if (sum == -1)
                return i;
            i++;
        }

        //录入格式不正确
        System.out.println("String Match Of()!");
        return -1;
    }

    /*
     * 寻找用户输入属性字符串的起始位置
     * 找到以下符号('(','C','c')返回当前index
     * 不以上述三种符号开头(录入格式错误)返回-1
     * */
    private int findBegin(char[] str, int begin, int end) {

        int i = begin;
        while ((str[i] == ' ') && (i <= end))
            i++;

        if (str[i] == '(' || str[i] == 'C' || str[i] == 'c')
            return i;

        //格式不正确
        return -1;
    }

    /*
     * 寻找and or关键字
     * 找到and or返回当前index
     * 没有关键字 返回-1
     * */
    private int findBeginAndOr(char[] str, int begin, int end) {

        int i = begin;

        while ((str[i] == ' ') && (i <= end))
            i++;

        if (str[i] == 'a' || str[i] == 'o')
            return i;
        //格式不正确
        return -1;
    }


    /*
     * 根据size初始化
     * */
    public void initialSize(int size, Pairing pairing) {
        // just take place
        m_count = size;

        m_Ano = new int[size];
        m_flag = new int[size];

        for (int i = 0; i < size; i++) {
            Element p1 = pairing.getZr().newElement();
            m_w.add(p1);
            Element p2 = pairing.getGT().newElement();
            m_result.add(p2);
            m_Ano[i] = size;
            m_flag[i] = size;
        }


    }


    /*
     * 字符串递归生成树
     *返回值类型GenTreeRes
     *返回值中 tree(CTree)为构造好的树
     *返回值中 control(int) 控制递归 。只用于函数内部构造使用，外部调用后可忽略该值
     * */
    public GenTreeRes genTree(GenTreeRes res, char[] str, int begin, int end1) {

        int k = 0;
        int end = 0;

        if (res.tree == null) {
            res.tree = new CTree();
            res.tree.m_child = new ArrayList<CTree>();
            for (int j = 0; j < 10; j++) {
                res.tree.m_child.add(j, null);
            }
        }

        int nb = findBegin(str, begin, end1);
        if (nb != -1) {
            if (str[nb] == '(') {
                //开始字符为(，仍为复合属性
                begin = nb + 1;
                end = findEnd(str, begin, end1) - 1;
            } else {
                //开始字符不是(，此时只有单一属性，即叶子节点
                res.tree.m_type = 0;
                res.tree.m_cno = str[nb + 1] - '0';
                res.control = end1;
                return res;
            }
        }

        int i = begin;
        int ne;

        //为复合属性生成树
        while (i <= end) {
//			System.out.println("000============tree============" + i);
            nb = findBegin(str, i, end);

            if (nb != -1) {
                if (str[nb] == '(') {
                    ne = findEnd(str, nb + 1, end);
                    GenTreeRes t = new GenTreeRes();
                    t.tree = res.tree.m_child.get(k);
                    t.control = i;
                    t = genTree(t, str, nb, ne);
                    res.tree.m_child.add(k, t.tree);
                    i = t.control;
                } else {
                    ne = nb + 1;
                    GenTreeRes t = new GenTreeRes();
                    t.tree = res.tree.m_child.get(k);
                    t.control = i;
                    t = genTree(t, str, nb, ne);
                    res.tree.m_child.add(k, t.tree);
                    i = t.control;
                }
                i++;
                k++;

                if (i <= end) {
                    nb = findBeginAndOr(str, i, end);
                    if (nb != -1) {
                        if (str[nb] == 'a') {
                            i = nb + 3;
                            res.tree.m_type = 1;
                        } else {

                            i = nb + 2;
                            res.tree.m_type = 2;
                        }
                    }
                }
            } else {
                //i = nb;
//			System.out.println("111=============tree=============" + i);
                break;
            }
        }

        res.control = end1;
        return res;
    }

    /*
     * 打印树结构
     * 打印内容为输入的属性逻辑
     * */
    public int printTree(CTree tree) {

        if (tree == null)
            return 0;

        if (tree.m_type == 0) {    //叶子节点
            System.out.print("C" + tree.m_cno);
            return 0;
        }

        System.out.print("(");
        Boolean start = true;

        for (int j = 0; j < 10 && tree.m_child.get(j) != null; j++) {
            if (!start)
                if (tree.m_type == 1)
                    System.out.print(" and ");
                else
                    System.out.print(" or ");
            else
                start = false;

            printTree(tree.m_child.get(j));
        }

        System.out.print(")");
        return 1;
    }


    /*
     * 生成密钥树 填充密码学元素
     * 构造share secret scheme
     *   mainsecret只赋值给叶节点
     *   and节点 将mainsecret拆分向下传
     *   or节点     保持mainsecret向下传
     * */
    public int genKeyTree(CTree tree, Element mainsecret, Pairing pairing) {

        if (tree == null) return 0;

        tree.m_s = pairing.getZr().newElement();
        tree.m_s.set(mainsecret);

        //叶节点
        if (tree.m_type == 0) {

            Element p = pairing.getZr().newElement();
            p.set(mainsecret);
            m_w.set(tree.m_cno, p);
            return 1;
        }

        int i;
        Element tmp, sum, buf;
        tmp = pairing.getZr().newElement();
        sum = pairing.getZr().newElement();
        buf = pairing.getZr().newElement();
        sum.setToZero();
        tmp.setToZero();

        //and逻辑
        if (tree.m_type == 1) {

            i = 0;
            while (tree.m_child.get(i) != null) {

                buf = sum.duplicate().add(tmp);
                sum.set(buf);
                tmp.setToRandom();
                genKeyTree(tree.m_child.get(i), tmp, pairing);
                i++;
            }

            tmp = mainsecret.duplicate().sub(sum);
            genKeyTree(tree.m_child.get(i - 1), tmp, pairing);

        } else {    //or 逻辑

            i = 0;
            while (tree.m_child.get(i) != null) {

                genKeyTree(tree.m_child.get(i), mainsecret, pairing);
                i++;
            }
        }

        return 1;
    }

    /*
     * 重构tree
     * */
    public int rebuiltKeyTree(CTree tree, Element res, Pairing pairing) {

        if (tree.m_type == 0) {

//			 res = tree.m_s;
            res.set(tree.m_s);

            return 1;
        }

        int i;
        Element tmp, sum;
        tmp = pairing.getZr().newElement();
        sum = pairing.getZr().newElement();
        tmp.setToZero();
        sum.setToZero();

        int b;
        if (tree.m_type == 1) {        //and逻辑

            i = 0;
            while (tree.m_child.get(i) != null) {

                b = rebuiltKeyTree(tree.m_child.get(i), tmp, pairing);
                if (b == 0) return 0;
                sum.add(tmp);
                i++;
            }

//			 res = sum;
            res.set(sum);

            return 1;
        } else {                     //or逻辑

            i = 0;
            while (tree.m_child.get(i) != null) {

                b = rebuiltKeyTree(tree.m_child.get(i), tmp, pairing);
                if (b == 1) {
//					 res = tmp;
                    res.set(tmp);
                    return 1;
                }
                i++;
            }
            return 0;
        }
    }

    public int rebuiltTree(CTree tree, Element res, Pairing pairing) {
        if (tree.m_type == 0) {          //叶子节点
            //m_flag初始化在本类中，赋值在其继承类的DecryptAttr()中
            //m_flag[index] == 1  即该节点尚未被处理
            if (m_flag[tree.m_cno] == 1) {
                tree.m_data = pairing.getGT().newElement();
                tree.m_data = m_result.get(tree.m_cno);
//				 res = tree.m_data;
                res.set(tree.m_data);
                return 1;
            } else
                return 0;
        }

        //非叶子节点
        int i;
        Element tmp, sum;
        tmp = pairing.getGT().newElement();
        sum = pairing.getGT().newElement();
        sum.setToOne();
        // tmp used as returned value
        tmp.setToOne();

        int b;
        if (tree.m_type == 1) {    //and节点
            i = 0;
            while (tree.m_child.get(i) != null) {
                b = rebuiltTree(tree.m_child.get(i), tmp, pairing);
                if (b == 0) return 0;
                sum.mul(tmp);
                i++;
            }
//			 res = sum;
            res.set(sum);
            return 1;
        } else {                    //or节点
            i = 0;
            while (tree.m_child.get(i) != null) {
                b = rebuiltTree(tree.m_child.get(i), tmp, pairing);
                if (b == 1) {
//					 res = tmp;
                    res.set(tmp);
                    return 1;
                }
                i++;
            }
            return 0;
        }
    }


    /*
     * 打印出错信息
     * 该函数由其继承类实现
     * */
    public int encryptAttr(SAttributeList attr, PublicKey pk, Pairing pairing) {

        System.out.println("This is a big error!");
        return 1;
    }


    /*
     * 打印出错信息
     * 该函数由其继承类实现
     * */
    public int decryptAttr(SAttributeList attr, SABEKey key, Pairing pairing) {

        System.out.println("This is a big error!");
        return 1;
    }
}
