(this.webpackJsonpclient=this.webpackJsonpclient||[]).push([[0],{27:function(e,t,n){},35:function(e,t,n){"use strict";n.r(t);var c=n(1),r=n.n(c),a=n(21),s=n.n(a),l=(n(27),n(10)),i=n(5),j="userData",o=n(2),u=n(4),b=n.n(u),d=n(9),O=n(14),h=n(13);function x(){}var p=Object(c.createContext)({token:null,userId:null,login:x,logout:x,isAuthenticated:!1}),f=function(){var e=Object(c.useState)(!1),t=Object(i.a)(e,2),n=t[0],r=t[1],a=Object(c.useState)(null),s=Object(i.a)(a,2),l=s[0],j=s[1];return{loading:n,request:Object(c.useCallback)(function(){var e=Object(d.a)(b.a.mark((function e(t){var n,c,a,s,l,i=arguments;return b.a.wrap((function(e){for(;;)switch(e.prev=e.next){case 0:return n=i.length>1&&void 0!==i[1]?i[1]:"GET",c=i.length>2&&void 0!==i[2]?i[2]:null,a=i.length>3&&void 0!==i[3]?i[3]:{},r(!0),e.prev=4,c&&(c=JSON.stringify(c),a["Content-Type"]="application/json"),e.next=8,fetch(t,{method:n,body:c,headers:a});case 8:return s=e.sent,e.next=11,s.json();case 11:if(l=e.sent,s.ok){e.next=14;break}throw new Error(l.message||"\u0427\u0442\u043e-\u0442\u043e \u043f\u043e\u0448\u043b\u043e \u043d\u0435 \u0442\u0430\u043a");case 14:return r(!1),e.abrupt("return",l);case 18:throw e.prev=18,e.t0=e.catch(4),r(!1),j(e.t0.message),e.t0;case 23:case"end":return e.stop()}}),e,null,[[4,18]])})));return function(t){return e.apply(this,arguments)}}(),[]),error:l,clearErrors:Object(c.useCallback)((function(){return j(null)}),[])}},v=n(0),m=function(){var e=Object(c.useContext)(p),t=Object(c.useCallback)((function(e){window.M&&e&&window.M.toast({html:e})}),[]),n=f(),r=n.loading,a=n.request,s=n.error,l=n.clearErrors,j=Object(c.useState)({email:"",password:""}),o=Object(i.a)(j,2),u=o[0],x=o[1];Object(c.useEffect)((function(){t(s),l()}),[s,t,l]);var m=function(e){x(Object(h.a)(Object(h.a)({},u),{},Object(O.a)({},e.target.name,e.target.value)))},g=function(){var e=Object(d.a)(b.a.mark((function e(){var n;return b.a.wrap((function(e){for(;;)switch(e.prev=e.next){case 0:return e.prev=0,e.next=3,a("/api/auth/register","POST",Object(h.a)({},u));case 3:n=e.sent,t(n.message),e.next=9;break;case 7:e.prev=7,e.t0=e.catch(0);case 9:case"end":return e.stop()}}),e,null,[[0,7]])})));return function(){return e.apply(this,arguments)}}(),k=function(){var t=Object(d.a)(b.a.mark((function t(){var n;return b.a.wrap((function(t){for(;;)switch(t.prev=t.next){case 0:return t.prev=0,t.next=3,a("/api/auth/login","POST",Object(h.a)({},u));case 3:n=t.sent,e.login(n.token,n.userId),t.next=9;break;case 7:t.prev=7,t.t0=t.catch(0);case 9:case"end":return t.stop()}}),t,null,[[0,7]])})));return function(){return t.apply(this,arguments)}}();return Object(v.jsx)("div",{className:"row",children:Object(v.jsxs)("div",{className:"col s6 offset-s3",children:[Object(v.jsx)("h1",{children:"\u0421\u043e\u043a\u0440\u0430\u0442\u0438 \u0441\u0441\u044b\u043b\u043a\u0443"}),Object(v.jsxs)("div",{className:"card grey lighten-3",children:[Object(v.jsxs)("div",{className:"card-content black-text",children:[Object(v.jsx)("span",{className:"card-title",children:"\u0410\u0432\u0442\u043e\u0440\u0438\u0437\u0430\u0446\u0438\u044f"}),Object(v.jsxs)("div",{children:[Object(v.jsxs)("div",{className:"input-field",children:[Object(v.jsx)("input",{id:"email",type:"email",name:"email",value:u.email,onChange:m}),Object(v.jsx)("label",{htmlFor:"email",children:"Email"})]}),Object(v.jsxs)("div",{className:"input-field",children:[Object(v.jsx)("input",{id:"password",type:"password",name:"password",value:u.password,onChange:m}),Object(v.jsx)("label",{htmlFor:"password",children:"Password"})]})]})]}),Object(v.jsxs)("div",{className:"card-action",children:[Object(v.jsx)("button",{className:"btn yellow darken-4",style:{marginRight:10},disabled:r,onClick:k,children:"\u0412\u043e\u0439\u0442\u0438"}),Object(v.jsx)("button",{className:"btn light-blue darken-1",onClick:g,disabled:r,children:"\u0420\u0435\u0433\u0438\u0441\u0442\u0440\u0430\u0446\u0438\u044f"})]})]})]})})},g=function(){var e=Object(o.g)(),t=Object(c.useContext)(p),n=f().request,r=Object(c.useState)(""),a=Object(i.a)(r,2),s=a[0],l=a[1],j=function(){var c=Object(d.a)(b.a.mark((function c(r){var a;return b.a.wrap((function(c){for(;;)switch(c.prev=c.next){case 0:if(console.log("work"),"Enter"!==r.key){c.next=12;break}return c.prev=2,console.log("Enter"),c.next=6,n("/api/link/generate","POST",{from:s},{Authorization:"Bearer ".concat(t.token)});case 6:a=c.sent,e.push("detail/".concat(a.link._id)),c.next=12;break;case 10:c.prev=10,c.t0=c.catch(2);case 12:case"end":return c.stop()}}),c,null,[[2,10]])})));return function(e){return c.apply(this,arguments)}}();return Object(v.jsx)("div",{className:"row",children:Object(v.jsx)("div",{className:"col s8 offset-s2",style:{paddingTop:"2rem"},children:Object(v.jsxs)("div",{className:"input-field",children:[Object(v.jsx)("input",{id:"link",type:"text",name:"link",value:s,onChange:function(e){return l(e.target.value)},onKeyPress:j}),Object(v.jsx)("label",{htmlFor:"email",children:"\u0412\u0441\u0442\u0430\u0432\u044c\u0442\u0435 \u0441\u0441\u044b\u043b\u043a\u0443"})]})})})},k=function(e){var t=e.link;return Object(v.jsxs)(v.Fragment,{children:[Object(v.jsx)("h2",{children:"\u0421\u0441\u044b\u043b\u043a\u0430"}),Object(v.jsxs)("p",{children:["\u0412\u0430\u0448\u0430 \u0441\u0441\u044b\u043b\u043a\u0430:"," ",Object(v.jsx)("a",{href:t.to,target:"_blank",rel:"noopener noreferrer",children:t.to})]}),Object(v.jsxs)("p",{children:["\u041e\u0442\u043a\u0443\u0434\u0430:"," ",Object(v.jsx)("a",{href:t.from,target:"_blank",rel:"noopener noreferrer",children:t.from})]}),Object(v.jsxs)("p",{children:["\u041a\u043e\u043b\u0438\u0447\u0435\u0441\u0442\u0432\u043e \u043a\u043b\u0438\u043a\u043e\u0432 \u043f\u043e \u0441\u0441\u044b\u043b\u043a\u0435: ",Object(v.jsx)("strong",{children:t.clicks})]}),Object(v.jsxs)("p",{children:["\u0414\u0430\u0442\u0430 \u0441\u043e\u0437\u0434\u0430\u043d\u0438\u044f:"," ",Object(v.jsx)("strong",{children:new Date(t.date).toLocaleDateString()})]})]})},w=function(){return Object(v.jsx)("div",{className:"preloader-wrapper big active",children:Object(v.jsxs)("div",{className:"spinner-layer spinner-blue-only",children:[Object(v.jsx)("div",{className:"circle-clipper left",children:Object(v.jsx)("div",{className:"circle"})}),Object(v.jsx)("div",{className:"gap-patch",children:Object(v.jsx)("div",{className:"circle"})}),Object(v.jsx)("div",{className:"circle-clipper right",children:Object(v.jsx)("div",{className:"circle"})})]})})},N=function(){var e=f(),t=e.request,n=e.loading,r=Object(c.useContext)(p).token,a=Object(c.useState)(null),s=Object(i.a)(a,2),l=s[0],j=s[1],u=Object(o.h)().id,O=Object(c.useCallback)(Object(d.a)(b.a.mark((function e(){var n;return b.a.wrap((function(e){for(;;)switch(e.prev=e.next){case 0:return e.prev=0,console.log(u),e.next=4,t("/api/link/".concat(u),"GET",null,{Authorization:"Bearer ".concat(r)});case 4:n=e.sent,j(n),e.next=10;break;case 8:e.prev=8,e.t0=e.catch(0);case 10:case"end":return e.stop()}}),e,null,[[0,8]])}))),[r,u,t]);return Object(c.useEffect)((function(){O()}),[O]),n?Object(v.jsx)(w,{}):Object(v.jsx)(v.Fragment,{children:!n&&l&&Object(v.jsx)(k,{link:l})})},y=function(e){var t=e.links;return t.length?Object(v.jsxs)("table",{children:[Object(v.jsx)("thead",{children:Object(v.jsxs)("tr",{children:[Object(v.jsx)("th",{children:"\u2116"}),Object(v.jsx)("th",{children:"\u041e\u0440\u0433\u0438\u043d\u0430\u043b\u044c\u043d\u0430\u044f"}),Object(v.jsx)("th",{children:"\u0421\u043e\u043a\u0440\u0430\u0449\u0435\u043d\u043d\u0430\u044f"}),Object(v.jsx)("th",{children:"\u041e\u0442\u043a\u0440\u044b\u0442\u044c"})]})}),Object(v.jsx)("tbody",{children:t.map((function(e,t){return Object(v.jsxs)("tr",{children:[Object(v.jsx)("td",{children:t+1}),Object(v.jsx)("td",{children:e.from}),Object(v.jsx)("td",{children:e.to}),Object(v.jsx)("td",{children:Object(v.jsx)(l.b,{to:"/detail/".concat(e._id),children:"\u041e\u0442\u043a\u0440\u044b\u0442\u044c"})})]},e._id)}))})]}):Object(v.jsx)("p",{className:"center",children:"\u0421\u0441\u044b\u043b\u043e\u043a \u043f\u043e\u043a\u0430 \u043d\u0435\u0442"})},C=function(){var e=Object(c.useState)([]),t=Object(i.a)(e,2),n=t[0],r=t[1],a=f(),s=a.loading,l=a.request,j=Object(c.useContext)(p).token,o=Object(c.useCallback)(Object(d.a)(b.a.mark((function e(){var t;return b.a.wrap((function(e){for(;;)switch(e.prev=e.next){case 0:return e.prev=0,e.next=3,l("/api/link","GET",null,{Authorization:"Bearer ".concat(j)});case 3:t=e.sent,r(t),e.next=9;break;case 7:e.prev=7,e.t0=e.catch(0);case 9:case"end":return e.stop()}}),e,null,[[0,7]])}))),[j,l]);return Object(c.useEffect)((function(){o()}),[o]),s?Object(v.jsx)(w,{}):Object(v.jsx)(v.Fragment,{children:!s&&Object(v.jsx)(y,{links:n})})},S=(n(34),function(){var e=Object(o.g)(),t=Object(c.useContext)(p);return Object(v.jsx)("nav",{children:Object(v.jsxs)("div",{className:"nav-wrapper blue darken-1",style:{padding:"0 2rem"},children:[Object(v.jsx)("span",{className:"brand-logo",children:"\u0421\u043e\u043a\u0440\u0430\u0449\u0435\u043d\u0438\u0435 \u0441\u0441\u044b\u043b\u043e\u043a"}),Object(v.jsxs)("ul",{id:"nav-mobile",className:"right hide-on-med-and-down",children:[Object(v.jsx)("li",{children:Object(v.jsx)(l.c,{to:"/create",children:"\u0421\u043e\u0437\u0434\u0430\u0442\u044c"})}),Object(v.jsx)("li",{children:Object(v.jsx)(l.c,{to:"/links",children:"\u0421\u0441\u043b\u043a\u0438"})}),Object(v.jsx)("li",{children:Object(v.jsx)("a",{href:"/",onClick:function(n){n.preventDefault(),t.logout(),e.push("/")},children:"\u0412\u044b\u0439\u0442\u0438"})})]})]})})});var E=function(){var e=function(){var e=Object(c.useState)(null),t=Object(i.a)(e,2),n=t[0],r=t[1],a=Object(c.useState)(!1),s=Object(i.a)(a,2),l=s[0],o=s[1],u=Object(c.useState)(null),b=Object(i.a)(u,2),d=b[0],O=b[1],h=Object(c.useCallback)((function(e,t){r(e),O(t),localStorage.setItem(j,JSON.stringify({userId:t,token:e}))}),[]),x=Object(c.useCallback)((function(){r(null),O(null),localStorage.removeItem(j)}),[]);return Object(c.useEffect)((function(){var e=JSON.parse(localStorage.getItem(j));e&&e.token&&h(e.token,e.userId),o(!0)}),[h]),{login:h,logout:x,token:n,userId:d,ready:l}}(),t=e.token,n=e.login,r=e.logout,a=e.userId,s=e.ready,u=!!t,b=function(e){return e?Object(v.jsxs)(o.d,{children:[Object(v.jsx)(o.b,{path:"/links",exact:!0,children:Object(v.jsx)(C,{})}),Object(v.jsx)(o.b,{path:"/create",exact:!0,children:Object(v.jsx)(g,{})}),Object(v.jsx)(o.b,{path:"/detail/:id",children:Object(v.jsx)(N,{})}),Object(v.jsx)(o.a,{to:"/create"})]}):Object(v.jsxs)(o.d,{children:[Object(v.jsx)(o.b,{path:"/",exact:!0,children:Object(v.jsx)(m,{})}),Object(v.jsx)(o.a,{to:"/"})]})}(u);return s?Object(v.jsx)(p.Provider,{value:{token:t,login:n,logout:r,userId:a,isAuthenticated:u},children:Object(v.jsxs)(l.a,{children:[u&&Object(v.jsx)(S,{}),Object(v.jsx)("div",{className:"container",children:b})]})}):Object(v.jsx)(w,{})},I=function(e){e&&e instanceof Function&&n.e(3).then(n.bind(null,36)).then((function(t){var n=t.getCLS,c=t.getFID,r=t.getFCP,a=t.getLCP,s=t.getTTFB;n(e),c(e),r(e),a(e),s(e)}))};s.a.render(Object(v.jsx)(r.a.StrictMode,{children:Object(v.jsx)(E,{})}),document.getElementById("root")),I()}},[[35,1,2]]]);
//# sourceMappingURL=main.480f3a71.chunk.js.map