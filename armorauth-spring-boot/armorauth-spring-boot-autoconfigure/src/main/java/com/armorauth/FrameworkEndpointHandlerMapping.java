package com.armorauth;

import com.armorauth.common.annotation.FrameworkEndpoint;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.AnnotationUtils;
import org.springframework.web.servlet.mvc.method.annotation.RequestMappingHandlerMapping;

public class FrameworkEndpointHandlerMapping extends RequestMappingHandlerMapping {


    public FrameworkEndpointHandlerMapping() {
        setOrder(Ordered.LOWEST_PRECEDENCE - 2);
    }

    @Override
    protected boolean isHandler(Class<?> beanType) {
        return AnnotationUtils.findAnnotation(beanType, FrameworkEndpoint.class) != null;
    }


}
