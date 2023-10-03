package com.asbe.bean;

import java.util.ArrayList;
import java.util.List;

public class CSetElementKey {
	// attribute-set number
	public int m_index;
	public String m_strID;
	public List<CElementKey> m_valueList;
	
	public CSetElementKey(){
		
		m_valueList = new ArrayList<CElementKey>();
	}
}
