package com.asbe.bean;

import it.unisa.dia.gas.jpbc.Element;

import java.util.ArrayList;
import java.util.List;

public class SetCipher {

	public List<String> ElementsOfSet;
	public Boolean[] subset; 
	public Type m_type;
	public Element c1;
	public Element c2;
	
	public SetCipher(){
		
		ElementsOfSet = new ArrayList<String>();
	}
}
