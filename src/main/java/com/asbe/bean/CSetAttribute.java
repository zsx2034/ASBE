package com.asbe.bean;

import java.util.ArrayList;
import java.util.List;

public class CSetAttribute extends CAttribute{

	public List<CElementOfSet> m_set;
	
	public CSetAttribute(){
		
		m_set = new ArrayList<CElementOfSet>();
	}
}
